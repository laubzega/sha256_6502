# sha256_6502
### Speed-optimized SHA-256 hashing for the venerable 6502.

Just-for-fun implementation of SHA-256. It is much more computationally
intensive than MD5, so this time I went for performance, code size be damned.
What resulted is probably the fastest SHA-256 for the 6502, hashing at a
blistering pace of 410 bytes/s on a C64. All that with a minimal use of ZP.
 
You will need cc65 (https://github.com/cc65/cc65) to build.

### How to use:

In order to calculate SHA-256 hash of a message:

1. Call `_sha256_init`.
2. Call `_sha256_next_block` for every 64-byte block of the message, passing a
   pointer to beginning of the block in A/X (lo/hi) and size of the block
   in Y. Only the final block's size can be smaller than 64 bytes!
3. Call `_sha256_finalize`.
4. Find computed SHA-256 hash in 32 bytes starting at `_sha256_hash`.

See `tests.s` for examples.

### Limitations

Currently messages of up to 2MiB are supported. This should not be a
problem in practice, but if the need arises, the limit can be increased easily.

### Testing

Sure. Run `make test`. If it fails, you optimized too much.

### Did you say Commodore 64?

Yes. `make sha256.prg` and have fun benchmarking.


### Author

Milek Smyk (@laubzega)
