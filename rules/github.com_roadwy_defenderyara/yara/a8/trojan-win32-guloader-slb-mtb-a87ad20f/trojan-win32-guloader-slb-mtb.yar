rule Trojan_Win32_Guloader_SLB_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SLB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {49 73 62 72 79 64 65 6e 64 65 2e 61 66 72 } 		$a_81_1 = {43 72 79 73 74 61 6c 69 7a 65 72 2e 53 79 6e } 		$a_81_2 = {6d 65 74 61 62 61 73 69 73 2e 73 74 65 } 		$a_81_3 = {70 6c 61 73 6d 6f 6c 79 7a 61 62 6c 65 2e 64 65 6d } 		$a_81_4 = {76 69 6e 64 73 70 69 6c 6c 65 72 2e 63 79 73 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}