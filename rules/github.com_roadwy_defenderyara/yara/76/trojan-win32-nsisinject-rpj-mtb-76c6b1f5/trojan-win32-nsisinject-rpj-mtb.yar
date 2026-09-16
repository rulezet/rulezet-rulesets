rule Trojan_Win32_NSISInject_RPJ_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {53 6f 66 74 77 61 72 65 5c 47 79 72 6f 69 64 61 6c 5c 54 65 6c 65 66 6f 6e 61 6e 6e 6f 6e 63 65 6e 5c 53 70 69 73 65 6f 6c 69 65 72 } 		$a_81_1 = {48 65 6d 61 74 69 6e 69 63 } 		$a_81_2 = {52 68 65 74 74 2e 69 6e 69 } 		$a_81_3 = {46 6f 72 73 6e 61 6b 6b 65 6c 73 65 } 		$a_81_4 = {53 6b 6f 76 76 73 6e 65 72 2e 64 6c 6c } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}