rule Trojan_Win32_NSISInject_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 70 68 61 63 65 6c 75 73 5c 53 6e 6e 69 6b 65 72 } 		$a_01_1 = {6b 72 79 70 74 65 72 69 6e 67 73 70 6f 6c 69 74 69 6b } 		$a_01_2 = {74 69 70 70 65 6c 61 64 65 74 } 		$a_01_3 = {53 70 72 79 64 73 74 61 67 65 72 6e 65 73 2e 69 6e 69 } 		$a_01_4 = {70 6e 68 65 64 73 2e 45 75 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}