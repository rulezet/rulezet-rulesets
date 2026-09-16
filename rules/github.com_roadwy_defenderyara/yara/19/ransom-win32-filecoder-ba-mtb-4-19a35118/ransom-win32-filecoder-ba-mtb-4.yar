rule Ransom_Win32_Filecoder_BA_MTB_4{
	meta:
		description = "Ransom:Win32/Filecoder.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_81_0 = {64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } 		$a_81_1 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 } 		$a_81_2 = {52 45 41 44 5f 4d 45 2e 54 58 54 } 		$a_81_3 = {48 45 4c 50 5f 50 43 2e 45 5a 44 5a 2d 52 45 4d 4f 56 45 2e 74 78 74 } 		$a_81_4 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 2e 62 69 6e } 	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=7
 
}