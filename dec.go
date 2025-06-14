package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
	"github.com/dustin/go-humanize"
	"github.com/panjf2000/ants/v2"
	"github.com/schollz/progressbar/v3"
)

const (
	chunkSize = 1 * 1024 * 1024 // 1MB
)

func setupLogging() *os.File {
	logFile, err := os.OpenFile("decryption_log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(logFile)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	return logFile
}

func loadPrivateKey(filename string) (age.Identity, error) {
	log.Printf("Loading private key from file: %s", filename)
	keyData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading private key file: %v", err)
	}
	privateKeyStr := strings.TrimSpace(string(keyData))
	id, err := age.ParseX25519Identity(privateKeyStr)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %v", err)
	}
	return id, nil
}

func decryptFile(inputFile, outputFile string, identity age.Identity) error {
	log.Printf("Starting decryption of file: %s", inputFile)
	startTime := time.Now()

	// Open input file
	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("error opening input file: %v", err)
	}
	defer inFile.Close()
	fileInfo, err := inFile.Stat()
	if err != nil {
		return fmt.Errorf("error getting file info: %v", err)
	}
	fileSize := fileInfo.Size()

	// Create output file with secure permissions
	outFile, err := os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err)
	}
	defer outFile.Close()

	// Initialize age reader
	decReader, err := age.Decrypt(inFile, identity)
	if err != nil {
		return fmt.Errorf("error initializing age reader: %v", err)
	}

	// Initialize progress bar
	bar := progressbar.NewOptions64(
		fileSize,
		progressbar.OptionSetDescription(fmt.Sprintf("Decrypting %s", filepath.Base(inputFile))),
		progressbar.OptionSetRenderBlankState(true),
		progressbar.OptionShowBytes(true),
		progressbar.OptionThrottle(100*time.Millisecond),
	)

	// Buffer for reading chunks
	buf := make([]byte, chunkSize)

	// Copy data from age reader to output file
	for {
		n, err := decReader.Read(buf)
		if n > 0 {
			if _, err := outFile.Write(buf[:n]); err != nil {
				return fmt.Errorf("error writing decrypted data: %v", err)
			}
			bar.Add(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("error reading encrypted data: %v", err)
		}
	}

	log.Printf("Decryption completed in %s. File size: %s",
		time.Since(startTime).Round(time.Second),
		humanize.Bytes(uint64(fileSize)),
	)
	return nil
}

func secureDelete(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("error stating file: %v", err)
	}

	// Overwrite 3 times with random data
	for i := 0; i < 3; i++ {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return fmt.Errorf("error opening file for overwrite: %v", err)
		}
		bar := progressbar.NewOptions64(
			info.Size(),
			progressbar.OptionSetDescription(fmt.Sprintf("Overwriting %s (pass %d)", filepath.Base(path), i+1)),
			progressbar.OptionSetRenderBlankState(true),
			progressbar.OptionShowBytes(true),
			progressbar.OptionThrottle(100*time.Millisecond),
		)
		buf := make([]byte, chunkSize)
		var written int64
		for written < info.Size() {
			_, err := rand.Read(buf)
			if err != nil {
				f.Close()
				return fmt.Errorf("error generating random data: %v", err)
			}
			n, err := f.Write(buf)
			if err != nil {
				f.Close()
				return fmt.Errorf("error overwriting file: %v", err)
			}
			written += int64(n)
			bar.Add(n)
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return fmt.Errorf("error syncing file: %v", err)
		}
		f.Close()
	}

	// Generate random suffix for new name
	randSuffix := make([]byte, 8)
	if _, err := rand.Read(randSuffix); err != nil {
		return fmt.Errorf("error generating random suffix: %v", err)
	}
	newName := filepath.Join(filepath.Dir(path), fmt.Sprintf(".%x", randSuffix))
	if err := os.Rename(path, newName); err != nil {
		return fmt.Errorf("error renaming file: %v", err)
	}
	return os.Remove(newName)
}

func recursiveDecrypt(dir string, identity age.Identity, pool *ants.Pool, wg *sync.WaitGroup) error {
	defer wg.Done()
	files, err := os.ReadDir(dir)
	if err != nil {
		log.Printf("Error reading directory %s: %v", dir, err)
		return err
	}
	for _, file := range files {
		path := filepath.Join(dir, file.Name())
		if file.IsDir() {
			wg.Add(1)
			pool.Submit(func() {
				recursiveDecrypt(path, identity, pool, wg)
			})
		} else if filepath.Ext(path) == ".fp1013Panda" {
			outputFile := path[:len(path)-len(".fp1013Panda")]
			wg.Add(1)
			pool.Submit(func() {
				defer wg.Done()
				if err := decryptFile(path, outputFile, identity); err != nil {
					log.Printf("Decryption failed for file %s: %v", path, err)
				}
				if err := secureDelete(path); err != nil {
					log.Printf("Error securely deleting file %s: %v", path, err)
				}
			})
		}
	}
	return nil
}

func main() {
	logFile := setupLogging()
	defer logFile.Close()
	log.Println("Starting decryption program")

	dir := flag.String("dir", "", "Directory to decrypt")
	keyFile := flag.String("key", "", "Path to the private key file")
	numWorkers := flag.Int("workers", 4, "Number of worker threads")
	flag.Parse()

	if *dir == "" || *keyFile == "" {
		log.Fatal("Both --dir and --key arguments required")
	}

	identity, err := loadPrivateKey(*keyFile)
	if err != nil {
		log.Fatalf("Error loading private key: %v", err)
	}

	pool, err := ants.NewPool(*numWorkers)
	if err != nil {
		log.Fatalf("Error creating pool: %v", err)
	}
	defer pool.Release()

	var wg sync.WaitGroup
	wg.Add(1)
	pool.Submit(func() {
		recursiveDecrypt(*dir, identity, pool, &wg)
	})

	wg.Wait()
	log.Println("Decryption process completed successfully")
}
