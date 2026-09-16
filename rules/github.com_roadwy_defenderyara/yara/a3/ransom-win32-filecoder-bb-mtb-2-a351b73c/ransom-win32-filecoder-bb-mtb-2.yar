rule Ransom_Win32_Filecoder_BB_MTB_2{
	meta:
		description = "Ransom:Win32/Filecoder.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {49 66 20 59 6f 75 20 77 61 6e 74 20 64 65 63 72 79 70 74 20 66 69 6c 65 73 20 70 6c 65 61 73 65 20 63 6f 6e 74 61 63 74 20 75 73 20 6f 6e 20 6a 61 62 62 65 72 3a } 		$a_81_1 = {70 61 79 6d 65 70 6c 65 61 73 65 40 73 6a 2e 6d 73 } 		$a_81_2 = {6a 75 73 74 66 69 6c 65 2e 74 78 74 } 		$a_81_3 = {49 4e 53 54 52 55 43 54 49 4f 4e 2e 74 78 74 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}