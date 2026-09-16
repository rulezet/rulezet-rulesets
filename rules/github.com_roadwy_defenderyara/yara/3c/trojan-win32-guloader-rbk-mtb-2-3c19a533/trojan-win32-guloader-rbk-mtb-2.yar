rule Trojan_Win32_GuLoader_RBK_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.RBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {5a 69 6f 6e 73 20 42 61 6e 63 6f 72 70 6f 72 61 74 69 6f 6e } 		$a_81_1 = {4d 69 72 61 6e 74 20 43 6f 72 70 6f 72 61 74 69 6f 6e } 		$a_81_2 = {52 65 67 69 6f 6e 73 20 46 69 6e 61 6e 63 69 61 6c 20 43 6f 72 70 2e } 		$a_81_3 = {61 6d 61 6c 67 61 6d 65 72 65 74 2e 65 78 65 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}