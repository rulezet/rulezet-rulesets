rule Ransom_Win32_Filecoder_BA_MTB_2{
	meta:
		description = "Ransom:Win32/Filecoder.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {41 4c 4c 20 59 4f 55 52 20 44 41 54 41 20 57 41 53 20 45 4e 43 52 59 50 54 45 44 } 		$a_81_1 = {5f 5f 6c 6f 63 6b 5f 58 58 58 5f 5f } 		$a_81_2 = {21 21 21 52 45 41 44 5f 4d 45 21 21 21 2e 74 78 74 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}