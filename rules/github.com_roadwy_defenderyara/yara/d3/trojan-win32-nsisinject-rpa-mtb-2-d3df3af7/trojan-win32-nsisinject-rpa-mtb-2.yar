rule Trojan_Win32_NSISInject_RPA_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {63 61 72 61 76 61 6e 65 72 73 } 		$a_81_1 = {55 6e 6e 6f 74 69 6f 6e 65 64 2e 62 6d 70 } 		$a_81_2 = {42 6c 61 61 6c 69 67 74 } 		$a_81_3 = {53 63 68 6f 72 6c 6f 6d 69 74 65 39 39 } 		$a_81_4 = {53 6f 66 74 77 61 72 65 5c 42 69 66 75 72 63 61 74 69 6f 6e 5c 57 65 6e 64 65 64 5c 4f 75 74 63 61 73 74 65 73 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}