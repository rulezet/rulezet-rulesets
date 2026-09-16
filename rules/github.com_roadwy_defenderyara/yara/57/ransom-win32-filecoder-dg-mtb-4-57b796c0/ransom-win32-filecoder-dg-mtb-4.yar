rule Ransom_Win32_Filecoder_DG_MTB_4{
	meta:
		description = "Ransom:Win32/Filecoder.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {2d 2d 2d 2d 2d 42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d } 		$a_81_1 = {2d 2d 2d 2d 2d 45 4e 44 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d } 		$a_81_2 = {53 43 48 54 41 53 4b 53 20 2f 44 45 4c 45 54 45 20 2f 54 4e 20 } 		$a_81_3 = {6e 65 74 77 6f 72 6b 61 75 74 6f 2e 74 6f 70 } 		$a_81_4 = {67 61 74 65 2e 70 68 70 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}