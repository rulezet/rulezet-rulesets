rule Trojan_BAT_FormBook_EVZ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EVZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {c0 8c c8 8c 65 77 cf 30 cc 28 0c b8 80 08 88 b8 2b ea b0 28 a0 08 82 42 81 0d 6e 93 19 77 71 25 6a 34 0b 1a 4d 40 a3 } 		$a_01_1 = {6d 6b cf 71 56 9c b3 74 75 db e9 4b d7 ac 71 d6 b7 9d 76 46 db 39 1b d6 b4 ad 5c d3 36 f3 98 13 da 56 3b cb ce e8 4a a7 cd f1 22 8d 63 67 49 d2 } 		$a_01_2 = {47 5a 69 70 53 74 72 65 61 6d } 		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}