rule Ransom_Win32_Filecoder_BA_MTB_3{
	meta:
		description = "Ransom:Win32/Filecoder.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {52 45 41 44 5f 4d 45 2e 74 78 74 } 		$a_81_1 = {63 6d 64 2e 65 78 65 20 2f 43 20 70 69 6e 67 20 31 2e 31 2e 31 2e 31 20 2d 6e 20 31 30 20 2d 77 20 33 30 30 30 20 3e 20 4e 75 6c 20 26 20 44 65 6c 20 2f 66 20 2f 71 20 22 25 73 22 } 		$a_81_2 = {63 3a 5c 31 31 31 5c 68 65 72 6d 65 73 5c 63 72 79 70 74 6f 70 70 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*2) >=3
 
}