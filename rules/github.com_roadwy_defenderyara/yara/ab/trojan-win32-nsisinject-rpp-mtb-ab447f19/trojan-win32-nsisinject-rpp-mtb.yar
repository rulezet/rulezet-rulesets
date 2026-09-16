rule Trojan_Win32_NSISInject_RPP_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {44 65 70 6f 6e 65 72 69 6e 67 73 6d 75 6c 69 67 68 65 64 } 		$a_81_1 = {42 6c 75 64 67 65 5c 4e 6f 6e 73 70 69 6e 6f 73 65 31 37 30 5c 4e 6f 6d 69 6e 61 74 69 76 61 6c 38 30 2e 69 6e 69 } 		$a_81_2 = {42 6f 77 65 72 79 69 73 68 32 32 31 2e 6c 6e 6b } 		$a_81_3 = {43 61 64 77 61 6c 2e 52 65 69 } 		$a_81_4 = {44 65 6c 69 67 68 74 65 72 2e 49 6e 67 34 35 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}