rule Trojan_Win32_NSISInject_RJ_MTB_4{
	meta:
		description = "Trojan:Win32/NSISInject.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 46 6f 72 74 79 6e 64 65 64 65 5c 4e 6f 6e 61 63 74 69 76 65 73 } 		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 55 70 72 6f 66 65 73 73 69 6f 6e 65 6c 5c 54 65 73 6b 65 66 75 6c 64 } 		$a_01_2 = {50 6f 73 69 74 73 2e 6c 6e 6b } 		$a_01_3 = {54 73 61 74 74 69 6e 65 5c 56 69 65 73 2e 69 6e 69 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}