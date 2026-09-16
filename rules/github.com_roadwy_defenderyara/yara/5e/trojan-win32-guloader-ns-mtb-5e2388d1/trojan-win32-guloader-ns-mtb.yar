rule Trojan_Win32_GuLoader_NS_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {74 69 6c 73 74 61 6e 64 73 66 6f 72 6d 2e 77 61 6c } 		$a_81_1 = {73 65 6b 75 6c 61 72 69 73 6d 65 6e 73 2e 74 72 65 } 		$a_81_2 = {69 6d 6d 69 67 72 61 74 69 6f 6e 65 6e 2e 6a 6f 6c } 		$a_81_3 = {63 69 6e 64 65 72 73 62 61 6e 65 72 6e 65 73 2e 66 69 63 } 		$a_81_4 = {6f 75 74 74 72 69 63 6b 69 6e 67 5c 44 65 74 65 6e 74 69 6f 6e 73 5c 6c 69 6e 69 65 66 72 69 6e 67 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}