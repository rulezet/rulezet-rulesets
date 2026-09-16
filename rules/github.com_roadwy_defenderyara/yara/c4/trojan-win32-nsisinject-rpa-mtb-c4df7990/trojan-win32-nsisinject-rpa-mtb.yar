rule Trojan_Win32_NSISInject_RPA_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 74 72 69 6b 6b 65 74 6a 65 74 } 		$a_01_1 = {42 6f 74 74 6f 6d 65 72 2e 43 61 78 32 32 38 } 		$a_01_2 = {44 79 62 66 72 6f 73 73 65 6e 2e 69 6e 69 } 		$a_01_3 = {62 65 6e 65 66 69 63 69 6e 67 5c 47 61 6c 61 68 61 64 73 2e 53 75 6e } 		$a_01_4 = {53 6f 63 69 61 6c 61 72 62 65 6a 64 65 2e 69 6e 69 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}