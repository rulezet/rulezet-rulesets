rule Ransom_Win32_Gulcrypt_A{
	meta:
		description = "Ransom:Win32/Gulcrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2a 2e 43 68 69 70 44 61 6c 65 } 		$a_01_1 = {50 49 4e 47 20 2d 6e 20 35 20 2d 77 20 31 30 30 30 20 31 32 37 2e 30 2e 30 2e 31 20 3e 20 6e 75 6c } 		$a_01_2 = {64 65 6c 20 73 79 73 74 65 6d 54 72 61 79 57 2e 65 78 65 } 		$a_01_3 = {00 63 68 69 70 5f 61 6e 64 5f 64 61 6c 65 2e 76 7a 68 6b 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}