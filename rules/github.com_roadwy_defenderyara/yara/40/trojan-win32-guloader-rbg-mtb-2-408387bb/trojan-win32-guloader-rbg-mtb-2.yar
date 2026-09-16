rule Trojan_Win32_GuLoader_RBG_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.RBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {4b 6e 69 67 68 74 2d 52 69 64 64 65 72 20 49 6e 63 2e } 		$a_81_1 = {56 69 61 64 20 43 6f 72 70 } 		$a_81_2 = {4d 65 64 74 72 6f 6e 69 63 20 49 6e 63 2e } 		$a_81_3 = {43 6f 6d 66 6f 72 74 20 53 79 73 74 65 6d 73 20 55 53 41 20 49 6e 63 2e } 		$a_81_4 = {75 6e 72 65 77 6f 72 64 65 64 20 64 65 6d 69 6d 6f 6e 64 6e 2e 65 78 65 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}