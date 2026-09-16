rule Ransom_Win32_Filecoder_DH_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {2e 63 72 79 70 74 } 		$a_81_1 = {4f 72 69 67 69 6e 61 6c 20 46 69 6c 65 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 64 65 6c 65 74 65 64 } 		$a_81_2 = {52 41 4e 53 4f 4d 2e 74 78 74 } 		$a_81_3 = {50 41 59 20 4d 45 20 42 49 54 43 4f 49 4e } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}