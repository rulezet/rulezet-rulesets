rule Ransom_Win32_Filecoder_DG_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {2e 72 61 70 69 64 } 		$a_81_1 = {21 20 48 6f 77 20 44 65 63 72 79 70 74 20 46 69 6c 65 73 2e 74 78 74 } 		$a_81_2 = {44 65 63 72 79 70 74 65 64 64 21 } 		$a_81_3 = {54 65 73 74 20 65 6e 63 72 79 70 74 20 66 61 69 6c 65 64 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}