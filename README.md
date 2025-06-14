Triple Pentester Team Present# BOENG
GO lang file enc use stable crypto libs age

--------------------------------------------------------
A simple, but kinda shabby encoder. It's not fancy, with no cool interfaces or frills. Just a command-line thing, one go file. But it's reliable.

It's unlikely to mess up your files. It's stable and doesn't have any magic tricks. It just takes a file and encodes it with an old, trusted format. Then it destroys the original file (overwrites it three times and then deletes it) if encryption was successful.
The good parts:
- Great encryption. It uses X25519 and ChaCha20-Poly1305, which are strong algorithms.
- Doesn't touch any unnecessary data. It preserves the file structure.
- Works well with big files, chunking them up.
- Makes a log so you can see what's going on.
- Removes restore points for Windows users.
Maybe it's not pretty, but it gets the job done.
- You'll need to manually use the "age -d" command to decrypt it.
- The ".fp1013Panda" extension without any settings is fixed.
If you're:
- Looking for a simple and secure way to encrypt your files, this is for you.
This method will ensure:
- No data will be compromised.
- Unexpected events won't happen.
And your original data will be totally wiped.
