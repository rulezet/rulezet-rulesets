rule Trojan_Win32_NSISInject_RB_MTB_5{
	meta:
		description = "Trojan:Win32/NSISInject.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 65 6c 69 6c 69 74 65 73 5c 54 6b 6b 65 74 } 		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 6d 69 73 66 6f 72 74 6f 6c 6b 6e 69 6e 67 65 6e 73 } 		$a_01_2 = {45 78 70 69 72 65 72 2e 69 6e 69 } 		$a_01_3 = {4c 69 76 73 66 61 72 65 6e 5c 43 68 72 69 6c 6c 65 73 73 2e 69 6e 69 } 		$a_01_4 = {43 6f 75 6e 74 65 72 73 68 61 64 69 6e 67 2e 69 6e 69 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}