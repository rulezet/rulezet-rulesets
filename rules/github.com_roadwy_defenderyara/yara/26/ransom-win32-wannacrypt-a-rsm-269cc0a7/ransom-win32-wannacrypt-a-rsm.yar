rule Ransom_Win32_WannaCrypt_A_rsm{
	meta:
		description = "Ransom:Win32/WannaCrypt.A!rsm,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {66 2e 77 6e 72 79 } 		$a_01_1 = {25 2e 31 66 20 42 54 43 } 		$a_01_2 = {40 57 61 6e 61 44 65 63 72 79 70 74 6f 72 40 2e 65 78 65 } 		$a_01_3 = {25 30 38 58 2e 65 6b 79 } 		$a_01_4 = {25 30 38 58 2e 70 6b 79 } 		$a_01_5 = {25 30 38 58 2e 72 65 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}