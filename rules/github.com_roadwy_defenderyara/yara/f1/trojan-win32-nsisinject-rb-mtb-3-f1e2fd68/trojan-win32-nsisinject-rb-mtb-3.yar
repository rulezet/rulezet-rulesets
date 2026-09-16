rule Trojan_Win32_NSISInject_RB_MTB_3{
	meta:
		description = "Trojan:Win32/NSISInject.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 72 65 65 6e 65 64 31 35 30 2e 69 6e 69 } 		$a_01_1 = {42 69 6c 6c 65 74 6b 6f 6e 74 6f 72 73 2e 53 63 79 } 		$a_01_2 = {45 66 74 65 72 73 6b 72 69 76 65 72 2e 64 6c 6c } 		$a_01_3 = {55 6e 69 6e 73 74 61 6c 6c 5c 54 68 72 61 73 68 65 72 73 } 		$a_01_4 = {4f 75 74 62 6c 61 7a 65 5c 6d 69 73 64 69 73 74 72 69 62 75 74 65 2e 69 6e 69 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}