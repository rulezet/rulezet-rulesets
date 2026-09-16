rule Ransom_Win32_FileCryptor_MAK_MTB{
	meta:
		description = "Ransom:Win32/FileCryptor.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {64 6f 63 75 6d 65 6e 74 73 20 6f 6e 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } 		$a_81_1 = {48 4f 57 5f 46 49 58 5f 46 49 4c 45 53 2e 68 74 6d } 		$a_81_2 = {72 61 6e 73 6f 6d 77 61 72 65 } 		$a_81_3 = {59 6f 75 72 20 50 65 72 73 6f 6e 61 6c 20 43 4f 44 45 3a } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}