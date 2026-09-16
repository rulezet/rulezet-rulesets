rule Trojan_Win32_NSISInject_RPF_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 79 64 65 70 6c 61 64 73 31 36 36 } 		$a_01_1 = {52 61 67 73 6f 6b 6b 65 72 5c 46 72 69 6d 6f 64 69 67 68 65 64 2e 52 65 70 } 		$a_01_2 = {53 74 6f 72 6c 69 6e 6a 65 64 65 73 5c 43 6f 75 6e 74 65 72 74 75 67 2e 6c 6e 6b } 		$a_01_3 = {53 6c 65 65 70 6d 61 72 6b 65 6e 5c 42 65 73 6d 69 74 74 65 6e 64 65 73 2e 69 6e 69 } 		$a_01_4 = {4b 75 70 6f 6e 6b 6c 69 70 70 65 72 65 6e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}