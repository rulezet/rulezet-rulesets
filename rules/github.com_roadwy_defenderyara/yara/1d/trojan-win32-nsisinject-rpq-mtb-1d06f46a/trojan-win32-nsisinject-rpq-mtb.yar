rule Trojan_Win32_NSISInject_RPQ_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {53 63 61 74 74 65 72 61 62 6c 65 5c 42 6f 6f 67 79 6d 65 6e } 		$a_81_1 = {54 65 6f 72 65 74 69 73 65 72 69 6e 67 65 6e } 		$a_81_2 = {53 6f 66 74 77 61 72 65 5c 45 6e 76 69 72 6f 6e 6d 65 6e 74 61 6c 69 73 74 33 30 5c 53 61 74 75 72 61 74 69 6e 67 } 		$a_81_3 = {53 69 64 65 72 69 74 65 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}