rule Trojan_Win32_GuLoader_RBN_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 69 65 64 20 57 61 73 74 65 20 49 6e 64 75 73 74 72 69 65 73 2c 20 49 6e 63 2e } 		$a_81_1 = {4d 65 74 61 6c 64 79 6e 65 20 43 6f 72 70 6f 72 61 74 69 6f 6e } 		$a_81_2 = {53 6f 75 74 68 77 65 73 74 20 41 69 72 6c 69 6e 65 73 20 43 6f } 		$a_81_3 = {66 6f 72 6d 62 6c 69 6e 67 65 6e 20 73 74 61 74 75 73 65 73 2e 65 78 65 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}