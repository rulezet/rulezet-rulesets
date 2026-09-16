rule Ransom_Win32_Filecoder_DG_MTB_3{
	meta:
		description = "Ransom:Win32/Filecoder.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_81_0 = {2f 63 20 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } 		$a_81_1 = {2e 72 61 70 69 64 } 		$a_81_2 = {48 6f 77 20 52 65 63 6f 76 65 72 79 20 46 69 6c 65 73 2e 74 78 74 } 		$a_81_3 = {72 61 70 69 64 40 61 69 72 6d 61 69 6c 2e 63 63 } 	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=5
 
}