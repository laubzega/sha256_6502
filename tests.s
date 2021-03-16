.export _main
.import _sha256_next_block, _sha256_init, _sha256_finalize
.import _sha256_hash
.import exit

    .segment "BSS"
counter: .res 1
test_idx: .res 1

; Run some tests from https://www.di-mgt.com.au/sha_testvectors.html
; and one additional, larger (16KB) text.
	.segment "STARTUP"
_main:
	lda #0
	sta test_idx
test_loop:
	jsr _sha256_init
	lda test_idx
	asl
	asl
	tay
	lda test_table,y
	pha
	ldx test_table + 1,y
	lda test_table + 2,y
	tay
	pla
	jsr _sha256_next_block
	jsr _sha256_finalize

	jsr verify_hash

	inc test_idx
	lda test_idx
	cmp #(test_table_end - test_table) / 4
	bne test_loop
	beq long_tests

verify_hash:
	ldx #0
	lda test_idx
	asl
	asl
	asl
	asl
	asl
	tay
hash_loop:
	lda hash_table,y
	cmp _sha256_hash,x
	bne error
	iny
	inx
	cpx #32
	bne hash_loop
	rts
error:
	ldx test_idx
	inx
	txa
	jmp exit
  

long_tests:    
	jsr _sha256_init
	lda #<data3
	ldx #>data3
	ldy #64
	jsr _sha256_next_block
 	lda #<(data3+64)
	ldx #>(data3+64)
	ldy #48
	jsr _sha256_next_block
	jsr _sha256_finalize

	jsr verify_hash

	inc test_idx

	lda #0		; loop 256 times for 64*256=16384 bytes
	sta counter
	jsr _sha256_init
next_block:
	lda #<data4
	ldx #>data4
	ldy #64
	jsr _sha256_next_block
	dec counter
	bne next_block
	jsr _sha256_finalize

	jsr verify_hash

	lda #0
	rts

	.SEGMENT "DATA"
test_table:
	.word data1, 0
	.word data1, 3
	.word data1, 56
	.word data2, 60
test_table_end:

hash_table:
	.dbyt $e3b0, $c442, $98fc, $1c14, $9afb, $f4c8, $996f, $b924, $27ae, $41e4, $649b, $934c, $a495, $991b, $7852, $b855
	.dbyt $ba78, $16bf, $8f01, $cfea, $4141, $40de, $5dae, $2223, $b003, $61a3, $9617, $7a9c, $b410, $ff61, $f200, $15ad
	.dbyt $248d, $6a61, $d206, $38b8, $e5c0, $2693, $0c3e, $6039, $a33c, $e459, $64ff, $2167, $f6ec, $edd4, $19db, $06c1
	.dbyt $decc, $538c, $0777, $8696, $6ac8, $63b5, $532c, $4027, $b858, $7ff4, $0f6e, $3103, $379a, $f62b, $44ea, $e44d

	.dbyt $cf5b, $16a7, $78af, $8380, $036c, $e59e, $7b04, $9237, $0b24, $9b11, $e8f0, $7a51, $afac, $4503, $7afe, $e9d1
	.dbyt $3068, $245f, $2ff3, $55cd, $d57c, $9f1d, $b9d6, $cd1f, $c6c0, $c906, $c729, $e7f4, $fbd4, $6b66, $ae75, $ebe4

data1:
	.byte "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
data2:
    .byte "123456789012345678901234567890123456789012345678901234567890"
data3:
	.byte "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
data4:
    .byte "123456789012345678901234567890123456789012345678901234567890123",10

; vim: set autoindent noexpandtab tabstop=4 shiftwidth=4 :
