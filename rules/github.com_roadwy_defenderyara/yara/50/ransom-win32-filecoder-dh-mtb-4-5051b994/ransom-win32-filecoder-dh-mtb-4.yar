rule Ransom_Win32_Filecoder_DH_MTB_4{
	meta:
		description = "Ransom:Win32/Filecoder.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d } 		$a_81_1 = {63 6d 64 2e 65 78 65 20 2f 63 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 3e 6e 75 6c 20 26 20 64 65 6c 20 2f 71 } 		$a_81_2 = {63 72 79 5f 64 65 6d 6f 2e 64 6c 6c } 		$a_81_3 = {63 6d 64 5f 73 68 61 64 6f 77 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}