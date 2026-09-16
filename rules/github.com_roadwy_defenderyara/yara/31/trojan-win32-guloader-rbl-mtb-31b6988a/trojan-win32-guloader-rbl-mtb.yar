rule Trojan_Win32_GuLoader_RBL_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {57 65 73 74 50 6f 69 6e 74 20 53 74 65 76 65 6e 73 20 49 6e 63 } 		$a_81_1 = {56 61 6c 76 65 20 43 6f 72 70 6f 72 61 74 69 6f 6e } 		$a_81_2 = {4d 65 64 74 72 6f 6e 69 63 20 49 6e 63 2e } 		$a_81_3 = {67 75 69 6c 74 69 65 73 74 2e 65 78 65 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}