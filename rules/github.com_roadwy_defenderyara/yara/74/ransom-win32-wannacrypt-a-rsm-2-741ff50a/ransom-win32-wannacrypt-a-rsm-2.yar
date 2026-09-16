rule Ransom_Win32_WannaCrypt_A_rsm_2{
	meta:
		description = "Ransom:Win32/WannaCrypt.A!rsm,SIGNATURE_TYPE_PEHSTR_EXT,fffffff4 01 fffffff4 01 05 00 00 "
		
	strings :
		$a_01_0 = {5f 5f 54 52 45 45 49 44 5f 5f 50 4c 41 43 45 48 4f 4c 44 45 52 5f 5f } 		$a_01_1 = {5f 5f 55 53 45 52 49 44 5f 5f 50 4c 41 43 45 48 4f 4c 44 45 52 5f 5f } 		$a_01_2 = {5f 5f 54 52 45 45 50 41 54 48 5f 52 45 50 4c 41 43 45 5f 5f } 		$a_01_3 = {74 61 73 6b 73 63 68 65 2e 65 78 65 } 		$a_01_4 = {71 65 72 69 75 77 6a 68 72 66 } 	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*100+(#a_01_4  & 1)*100) >=500
 
}