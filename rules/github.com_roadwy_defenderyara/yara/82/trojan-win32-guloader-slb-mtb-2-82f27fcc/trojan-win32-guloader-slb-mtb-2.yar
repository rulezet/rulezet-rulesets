rule Trojan_Win32_Guloader_SLB_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.SLB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {74 69 6c 73 6c 75 74 6e 69 6e 67 73 74 6f 67 65 73 20 76 69 67 74 65 6e 64 65 20 65 6e 74 75 73 69 61 73 74 } 		$a_81_1 = {74 69 6c 64 6e 67 65 64 65 20 65 6e 74 6f 6d 6f 74 6f 6d 69 73 74 20 74 72 69 6e 73 6b 69 66 74 65 72 6e 65 } 		$a_81_2 = {6d 75 6c 74 69 66 69 6c 65 72 20 73 68 65 6e 64 66 75 6c 2e 65 78 65 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}