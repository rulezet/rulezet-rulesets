rule Trojan_Win32_NSISInject_RPD_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4b 69 72 6b 65 67 61 61 72 64 73 6a 6f 72 64 65 6e 65 5c 54 72 75 5c 44 6f 6e 6b 65 79 6d 6e 64 65 6e 65 73 5c 50 61 72 61 6c 79 73 65 72 69 6e 67 65 72 6e 65 73 } 		$a_01_1 = {4b 61 79 6f 69 6e 67 2e 64 6c 6c } 		$a_01_2 = {56 65 6e 69 73 6f 6e 6c 69 6b 65 } 		$a_01_3 = {56 61 6e 64 6c 65 64 6e 69 6e 67 73 61 66 67 69 66 74 65 72 } 		$a_01_4 = {54 72 6b 6b 72 6f 67 65 6e 65 73 2e 41 73 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}