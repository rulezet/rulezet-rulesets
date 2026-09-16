rule Ransom_Win32_Filecoder_DG_MTB_2{
	meta:
		description = "Ransom:Win32/Filecoder.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {2e 67 75 65 73 73 77 68 6f } 		$a_81_1 = {54 65 73 74 20 64 65 63 72 79 70 74 20 66 61 69 6c 65 64 } 		$a_81_2 = {44 45 43 52 59 50 54 45 44 } 		$a_81_3 = {48 6f 77 20 52 65 63 6f 76 65 72 79 20 46 69 6c 65 73 2e 74 78 74 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}