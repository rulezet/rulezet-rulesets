rule Ransom_Win32_Filecoder_BA_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {2e 43 4f 4e 54 49 } 		$a_81_1 = {48 4f 57 5f 54 4f 5f 44 45 43 52 59 50 54 2e 74 78 74 } 		$a_81_2 = {24 52 45 43 59 43 4c 45 2e 42 49 4e } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}