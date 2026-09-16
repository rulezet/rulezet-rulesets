rule Trojan_Win32_GuLoader_RBH_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {70 6c 61 74 69 6c 6c 61 20 74 72 69 65 74 68 79 6c 73 74 69 62 69 6e 65 20 73 70 69 73 65 62 6c 65 72 73 } 		$a_81_1 = {73 61 74 61 6e 69 73 6d 20 66 61 69 72 6d } 		$a_81_2 = {79 61 72 6d 65 6c 6b 65 20 67 61 75 6e 74 2e 65 78 65 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}