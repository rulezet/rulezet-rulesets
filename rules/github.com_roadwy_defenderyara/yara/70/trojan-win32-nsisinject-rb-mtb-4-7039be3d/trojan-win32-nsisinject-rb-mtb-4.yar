rule Trojan_Win32_NSISInject_RB_MTB_4{
	meta:
		description = "Trojan:Win32/NSISInject.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 6f 6c 62 72 6d 61 72 6d 65 6c 61 64 65 73 2e 4b 75 72 } 		$a_01_1 = {53 74 72 75 6e 6b 65 2e 69 6e 69 } 		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 53 79 73 74 65 6d 66 75 6e 6b 74 69 6f 6e 65 72 6e 65 } 		$a_01_3 = {46 6f 72 62 6c 64 6e 69 6e 67 65 72 73 5c 52 61 74 74 65 64 2e 69 6e 69 } 		$a_01_4 = {44 65 6d 6f 6b 72 61 74 69 73 65 72 65 74 2e 56 69 7a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}