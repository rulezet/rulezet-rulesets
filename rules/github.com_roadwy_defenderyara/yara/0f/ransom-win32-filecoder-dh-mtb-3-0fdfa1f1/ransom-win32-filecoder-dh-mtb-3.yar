rule Ransom_Win32_Filecoder_DH_MTB_3{
	meta:
		description = "Ransom:Win32/Filecoder.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {48 6f 77 5f 5f 74 6f 5f 5f 64 65 63 72 79 70 74 5f 5f 66 69 6c 65 73 2e 74 78 74 } 		$a_81_1 = {49 54 45 52 41 54 4f 52 20 4c 49 53 54 20 43 4f 52 52 55 50 54 45 44 21 } 		$a_81_2 = {73 69 63 63 6b 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } 		$a_81_3 = {42 54 43 20 57 61 6c 6c 65 74 20 3a } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}