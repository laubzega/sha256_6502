; ok for C64, adjust for other platforms
data_ptr = $35

	.segment "BSS"
_buffer:
	.res 64*4
AA:	.res 4
BB:	.res 4
CC:	.res 4
DD:	.res 4
EE:	.res 4
FF:	.res 4
GG:	.res 4
HH:	.res 4

h0:	.res 4
h1:	.res 4
h2:	.res 4
h3:	.res 4
h4:	.res 4
h5:	.res 4
h6:	.res 4
h7:	.res 4

S0:	.res 4
S1:	.res 4
ch:	.res 4
maj: .res 4
temp1: .res 4

	; zeropage the most often used variables
	.ifdef __C64__
F3 = $fb
F2 = $fc
F1 = $fd
F0 = $fe
	.else
F3:	.res 1
F2:	.res 1
F1:	.res 1
F0:	.res 1
	.endif

final_block_size: .res 1
block_counter: .res 3

.import popa
.export _sha256_init, _sha256_finalize
.export _buffer, _sha256_next_block, _sha256_next_block_fastcall
.export _sha256_hash

_sha256_hash = h0

	.SEGMENT "CODE"
; 32-bit addition: src + dst -> dst
.macro add_32 src, dst
	clc
	.repeat 4, I
	lda src + (3-I)
	adc dst + (3-I)
	sta dst + (3-I)
	.endrep
.endmacro

; 32-bit AND: src AND dst -> dst
.macro and_32 src, dst
	.repeat 4, I
	lda src + I
	and dst + I
	sta dst + I
	.endrep
.endmacro

; 32-bit move: dst -> src
.macro mov_32 src, dst
	.repeat 4, I
	lda src + I
	sta dst + I
	.endrep
.endmacro

; 32-bit move & ror 8: dst -> src
.macro mov_ror8_32 src, dst
	.repeat 4, I
	lda src + I
	sta dst + ((I + 1) .mod 4)
	.endrep
.endmacro

; 32-bit move & ror 16: dst -> src
.macro mov_ror16_32 src, dst
	.repeat 4, I
	lda src + I
	sta dst + ((I + 2) .mod 4)
	.endrep
.endmacro

; 32-bit move & ror 24: dst -> src
.macro mov_ror24_32 src, dst
	.repeat 4, I
	lda src + I
	sta dst + ((I + 3) .mod 4)
	.endrep
.endmacro

; 32-bit XOR: src XOR dst -> dst
.macro xor_32 src, dst
	.repeat 4, I
	lda src + I
	eor dst + I
	sta dst + I
	.endrep
.endmacro


; Call this first before starting new hash computation.
; -----------------------------------------------------
_sha256_init:
	ldx #(4 * 8) - 1
init_const:
	lda initial_consts,x
	sta h0,x
	dex
	bpl init_const

	lda #0
	sta block_counter
	sta block_counter + 1
	sta block_counter + 2
	rts

copy_block_to_buffer:
	dey		; copy block to our internal buffer
copy_loop:	; so that we can pad at will
	lda (data_ptr),y
	sta _buffer,y
	dey
	bpl copy_loop
	rts

; Pad the buffer with zeros
; Y holds the index (0 based) of the last data byte
pad_buffer:
	lda #0
next_pad_byte:
	iny
	cpy #64
	beq padding_done
	sta _buffer,y
	bne next_pad_byte
padding_done:
	lda #<_buffer	; we'll be using the copy of the block
	sta data_ptr
	lda #>_buffer
	sta data_ptr + 1
	rts

; Calculate the total message size in bits
calc_total_bits:
	; convert block counter to bit counter
	; multiply by 512 by assuming implicit LSByte (zero)
	clc
	asl block_counter
	rol block_counter + 1
	rol block_counter + 2

	; now add bits from the final block
	clc
	lda final_block_size
	asl
	asl
	asl
	bcc no_bit_overflow
	inc block_counter + 1
	clc
no_bit_overflow:
	adc block_counter
	sta block_counter
	bcc no_carry2
	inc block_counter + 1
no_carry2:
; Append size of the original message (in bits) at
; the end of the final block. Assumes that block_counter
; has been converted to bits already.
	lda block_counter + 2
	sta _buffer + 61
	lda block_counter + 1
	sta _buffer + 62
	lda block_counter + 0
	sta _buffer + 63
	rts

; Call _after_ hashing the final message block.
_sha256_finalize:
	lda final_block_size
	cmp #56
	bcs extra_block
	rts
extra_block:
	ldy #255
	cmp #64
	bcc no_1_bit
	iny
	lda #$80
	sta _buffer,y
no_1_bit:
	jsr pad_buffer
	jmp append


; Same as _sha256_next_block, but using _fastcall_ argument passing convention.
;---------------------------------------------------------------------------
_sha256_next_block_fastcall:
	sta data_ptr
	stx data_ptr + 1
	jsr popa
	tay
	jmp sha256_skip_ptr
	
	
; Calculate hash of a block of up to 64-bytes. All message blocks MUST have
; 64 bytes except for the last one (which may be shorter).
;---------------------------------------------------------------------------
_sha256_next_block:
	sta data_ptr
	stx data_ptr + 1
sha256_skip_ptr:
	sty final_block_size
	cpy #64
	bne not_plain_block
	jsr copy_block_to_buffer
	jmp normal_block
not_plain_block:
	cpy #0
	beq append_1_bit	; empty block
	jsr copy_block_to_buffer
append_1_bit:
	ldy final_block_size
	lda #$80		; add extra "1" bit right after the data
	sta _buffer,y
padding:
	jsr pad_buffer

	ldy final_block_size
	cpy #56
	bcs size_wont_fit
append:
	jsr calc_total_bits

normal_block:
	inc block_counter + 1
	bne no_carry
	inc block_counter + 2
no_carry:
size_wont_fit:


_sha256:
	ldx #16*4
expand_loop:
.ifdef __C64__
	stx $d020
.endif
	; rightrotate 7
	.repeat 4,I
	lda _buffer+I-15*4,x
	sta	F3 + (I + 1) .mod 4
	.endrep

	jsr rol1
	mov_32 F3, S0

	; rightrotate 18
	.repeat 4,I
	lda _buffer+I-15*4,x
	sta	F3 + (I + 2) .mod 4
	.endrep

	jsr ror2
	xor_32 F3, S0

	; rightshift 3
	.repeat 4,I
	lda _buffer+I-15*4,x
	sta	F3 + I
	.endrep

	.repeat 3
	lsr F3
	ror F2
	ror F1
	ror	F0
	.endrep
	
	xor_32 F3, S0


	; rightrotate 17
	.repeat 4,I
	lda _buffer+I-2*4,x
	sta	F3 + (I + 2) .mod 4
	.endrep

	jsr ror1
	mov_32 F3, S1

	; rightrotate 19
	.repeat 4,I
	lda _buffer+I-2*4,x
	sta	F3 + (I + 2) .mod 4
	.endrep

	jsr ror3
	xor_32 F3, S1

	; rightshift 10
	.repeat 3,I
	lda _buffer+I-2*4,x
	sta	F2 + I
	.endrep

	lda #0
	sta F3
	.repeat 2
	lsr F2
	ror F1
	ror	F0
	.endrep
	
	xor_32 F3, S1

	; w[i] := w[i-16] + s0 + w[i-7] + s1
	add_32 S0,S1

	clc
	.repeat 4,I
	lda _buffer+(3-I)-16*4,x
	adc _buffer+(3-I)- 7*4,x
	sta S0+(3-I)
	.endrep

	clc
	.repeat 4,I
	lda S0+(3-I)
	adc S1+(3-I)
	sta _buffer+(3-I),x
	.endrep


	.repeat 4
	inx
	.endrep

	beq	end_expand_loop
	jmp	expand_loop
end_expand_loop:


	ldx #(4 * 8) - 1
init_loop:
	lda h0,x
	sta AA,x
	dex
	bpl init_loop

	ldx #0
main_loop:
.ifdef __C64__
	inc $d020
.endif
	; S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
	; rightrotate 6
	mov_ror8_32 EE,F3
	jsr	rol2
	mov_32 F3, S1

	; rightrotate 11
	mov_ror8_32 EE, F3
	jsr ror3
	xor_32 F3, S1

	; rightrotate 25
	mov_ror24_32 EE, F3
	jsr ror1
	xor_32 F3, S1

	; ch := (e and f) xor ((not e) and g)
	.repeat 4,I
	lda	#255
	eor EE+I
	and GG+I
	sta ch+I
	lda EE+I
	and FF+I
	eor ch+I
	sta ch+I
	.endrep

	; temp1 := h + S1 + ch + k[i] + w[i]
	add_32 HH, S1
	add_32 ch, S1

	clc
	.repeat 4,I
	lda _buffer+(3-I),x
	adc k_table+(3-I),x
	sta temp1+(3-I)
	.endrep

	add_32 S1, temp1

	; S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
	; rightrotate 2
	mov_32 AA, F3
	jsr	ror2
	mov_32 F3, S0

	; rightrotate 13
	mov_ror16_32 AA, F3
	jsr rol3
	xor_32 F3, S0

	; rightrotate 22
	mov_ror24_32 AA, F3
	jsr rol2
	xor_32 F3, S0

	; maj := (a and b) xor (a and c) xor (b and c)
	.repeat 4,I
	lda AA+I
	and BB+I
	sta maj+I 
	lda AA+I
	and CC+I
	eor maj+I
	sta maj+I
	lda BB+I
	and CC+I
	eor maj+I
	sta maj+I
	.endrep

	add_32 S0, maj

	mov_32 GG,HH
	mov_32 FF,GG
	mov_32 EE,FF
	mov_32 DD,EE
	add_32 temp1,EE
	mov_32 CC,DD
	mov_32 BB,CC
	mov_32 AA, BB
	mov_32 temp1,AA
	add_32 maj,AA

	inx
	inx
	inx
	inx

	beq end_main_loop
	jmp main_loop
end_main_loop:

	add_32 AA, h0
	add_32 BB, h1
	add_32 CC, h2
	add_32 DD, h3
	add_32 EE, h4
	add_32 FF, h5
	add_32 GG, h6
	add_32 HH, h7

	rts

; Generate rol1, rol2, rol3, ror1, ror2, ror3 routines.
	.repeat 3,SHIFT
	.ident (.concat ("rol", .string(3-SHIFT))):
	.repeat 3-SHIFT
	lda F3
	asl
	rol F0
	rol F1
	rol F2
	rol F3
	.endrep
	rts
	.endrep

	.repeat 3,SHIFT
	.ident (.concat ("ror", .string(3-SHIFT))):
	.repeat 3-SHIFT
	lda F0
	lsr
	ror F3
	ror F2
	ror F1
	ror F0
	.endrep
	rts
	.endrep


.segment "DATA"
k_table:
	.dbyt $428a, $2f98, $7137, $4491, $b5c0, $fbcf, $e9b5, $dba5, $3956, $c25b, $59f1, $11f1, $923f, $82a4, $ab1c, $5ed5
	.dbyt $d807, $aa98, $1283, $5b01, $2431, $85be, $550c, $7dc3, $72be, $5d74, $80de, $b1fe, $9bdc, $06a7, $c19b, $f174
	.dbyt $e49b, $69c1, $efbe, $4786, $0fc1, $9dc6, $240c, $a1cc, $2de9, $2c6f, $4a74, $84aa, $5cb0, $a9dc, $76f9, $88da
	.dbyt $983e, $5152, $a831, $c66d, $b003, $27c8, $bf59, $7fc7, $c6e0, $0bf3, $d5a7, $9147, $06ca, $6351, $1429, $2967
	.dbyt $27b7, $0a85, $2e1b, $2138, $4d2c, $6dfc, $5338, $0d13, $650a, $7354, $766a, $0abb, $81c2, $c92e, $9272, $2c85
	.dbyt $a2bf, $e8a1, $a81a, $664b, $c24b, $8b70, $c76c, $51a3, $d192, $e819, $d699, $0624, $f40e, $3585, $106a, $a070
	.dbyt $19a4, $c116, $1e37, $6c08, $2748, $774c, $34b0, $bcb5, $391c, $0cb3, $4ed8, $aa4a, $5b9c, $ca4f, $682e, $6ff3
	.dbyt $748f, $82ee, $78a5, $636f, $84c8, $7814, $8cc7, $0208, $90be, $fffa, $a450, $6ceb, $bef9, $a3f7, $c671, $78f2

initial_consts:
	.dbyt $6a09, $e667
	.dbyt $bb67, $ae85
	.dbyt $3c6e, $f372
	.dbyt $a54f, $f53a
	.dbyt $510e, $527f
	.dbyt $9b05, $688c
	.dbyt $1f83, $d9ab
	.dbyt $5be0, $cd19

; vim: set autoindent noexpandtab tabstop=4 shiftwidth=4 :
