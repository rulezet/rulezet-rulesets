rule Trojan_Win32_NSISInject_RPS_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {54 6a 61 6e 74 69 6e 67 2e 4d 65 6e } 		$a_81_1 = {43 6f 65 6e 6f 62 6c 61 73 74 69 63 2e 69 6e 69 } 		$a_81_2 = {42 6f 75 72 62 6f 6e 69 73 74 33 39 } 		$a_81_3 = {53 6f 66 74 77 61 72 65 5c 54 69 74 74 65 72 65 72 73 5c 53 61 6e 6a 61 6b 62 65 67 5c 4f 6c 69 65 66 6f 72 75 72 65 6e 65 6e 64 65 73 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}