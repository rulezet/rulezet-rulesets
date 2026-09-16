rule Ransom_Win32_Filecoder_MA_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b c6 99 f7 f9 8a 44 15 ec 30 04 1e 46 3b f7 7c ef } 		$a_01_1 = {6f 75 74 70 75 74 2e 74 78 74 } 		$a_01_2 = {44 65 63 72 79 70 74 4d 65 73 73 61 67 65 } 		$a_01_3 = {3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 64 65 73 6b 74 6f 70 2e 6a 70 67 } 		$a_01_4 = {66 75 63 6b 6d 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}