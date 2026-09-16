rule Trojan_Win32_GuLoader_RBD_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.RBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {6b 69 72 6b 65 67 61 6e 67 65 5c 62 61 6c 74 68 65 75 73 5c 64 69 67 72 65 73 73 69 6f 6e } 		$a_81_1 = {50 72 65 63 6f 73 6d 69 63 61 6c 6c 79 5c 6d 75 6c 74 69 68 65 61 64 } 		$a_81_2 = {25 73 65 61 63 72 6f 73 73 25 5c 73 6f 6c 63 72 65 6d 65 } 		$a_81_3 = {5c 6e 6f 6f 6b 79 5c 43 6f 6e 63 6f 6c 6f 75 72 2e 69 6e 69 } 		$a_81_4 = {5c 73 70 65 72 6d 61 74 69 61 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}