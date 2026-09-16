rule Trojan_Win32_NSISInject_RPZ_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 61 6c 76 74 72 65 64 73 61 61 72 69 67 65 5c 73 75 6e 6e 69 74 74 65 6e 73 5c 52 67 74 65 6e 64 65 } 		$a_01_1 = {53 6c 61 76 65 6e 73 2e 73 75 62 } 		$a_01_2 = {4b 6f 6d 6d 69 73 73 69 6f 6e 65 72 65 31 39 38 } 		$a_01_3 = {4d 61 72 6d 6f 72 68 76 69 64 74 2e 53 70 72 } 		$a_01_4 = {44 69 70 68 65 6e 6f 78 79 6c 61 74 65 2e 4e 61 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}