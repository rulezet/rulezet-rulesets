rule Ransom_Win32_Filecoder_DH_MTB_2{
	meta:
		description = "Ransom:Win32/Filecoder.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {4f 6f 6f 70 73 2c 20 79 6f 75 72 20 68 6f 6d 65 77 6f 72 6b 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 } 		$a_81_1 = {57 61 6e 6e 61 44 65 63 72 79 70 74 6f 72 } 		$a_81_2 = {2e 73 68 69 74 } 		$a_81_3 = {65 6e 63 72 79 70 74 46 69 6c 65 4e 61 6d 65 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}