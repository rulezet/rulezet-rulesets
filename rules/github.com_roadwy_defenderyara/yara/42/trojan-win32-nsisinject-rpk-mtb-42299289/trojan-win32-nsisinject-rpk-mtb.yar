rule Trojan_Win32_NSISInject_RPK_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {42 75 6f 6c 5c 61 72 69 74 68 6d 65 74 69 63 2e 69 6e 69 } 		$a_81_1 = {73 69 64 65 62 6f 61 72 64 5c 67 65 6e 6f 74 6f 78 69 63 69 74 79 2e 62 69 6e } 		$a_81_2 = {6d 61 72 6b 65 72 62 6f 61 72 64 5c 73 65 63 72 65 74 61 69 72 65 5c 61 63 63 65 70 74 61 6e 74 2e 74 78 74 } 		$a_81_3 = {66 61 63 65 6c 65 73 73 2e 64 6f 63 78 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}