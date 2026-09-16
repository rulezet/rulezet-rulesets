rule Trojan_BAT_Jalapeno_NJ_MTB_5{
	meta:
		description = "Trojan:BAT/Jalapeno.NJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 a3 00 00 0a 0a 28 e3 01 00 06 0b 07 1f 20 8d 58 00 00 01 25 d0 6a 02 00 04 28 8b 00 00 0a 6f c8 00 00 0a 07 1f 10 8d 58 00 00 01 25 d0 6c 02 00 04 28 8b 00 00 0a 6f c9 00 00 0a } 		$a_01_1 = {6f ca 00 00 0a 17 73 a4 00 00 0a 25 02 16 02 8e 69 6f a5 00 00 0a 6f a8 00 00 0a 06 6f a7 00 00 0a } 		$a_01_2 = {73 65 74 5f 43 6c 69 65 6e 74 43 72 65 64 65 6e 74 69 61 6c } 		$a_01_3 = {57 69 6e 64 6f 77 73 41 70 70 6c 69 63 61 74 69 6f 6e 31 31 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}