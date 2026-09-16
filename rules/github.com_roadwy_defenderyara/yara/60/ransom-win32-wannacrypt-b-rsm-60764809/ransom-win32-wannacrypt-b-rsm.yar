rule Ransom_Win32_WannaCrypt_B_rsm{
	meta:
		description = "Ransom:Win32/WannaCrypt.B!rsm,SIGNATURE_TYPE_PEHSTR_EXT,fffffff4 01 fffffff4 01 05 00 00 "
		
	strings :
		$a_01_0 = {47 6c 6f 62 61 6c 5c 4d 73 57 69 6e 5a 6f 6e 65 73 43 61 63 68 65 43 6f 75 6e 74 65 72 4d 75 74 65 78 41 } 		$a_01_1 = {74 61 73 6b 73 63 68 65 2e 65 78 65 } 		$a_01_2 = {57 4e 63 72 79 40 32 6f 6c 37 } 		$a_01_3 = {74 2e 77 6e 72 79 } 		$a_01_4 = {54 61 73 6b 53 74 61 72 74 } 	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*100+(#a_01_4  & 1)*100) >=500
 
}