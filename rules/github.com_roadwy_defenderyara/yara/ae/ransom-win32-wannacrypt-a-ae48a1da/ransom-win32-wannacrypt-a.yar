rule Ransom_Win32_WannaCrypt_A_{
	meta:
		description = "Ransom:Win32/WannaCrypt.A!!WannaCrypt.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {6c 61 75 6e 63 68 65 72 2e 64 6c 6c 00 50 6c 61 79 47 61 6d 65 00 } 		$a_00_1 = {6d 73 73 65 63 73 76 63 2e 65 78 65 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}