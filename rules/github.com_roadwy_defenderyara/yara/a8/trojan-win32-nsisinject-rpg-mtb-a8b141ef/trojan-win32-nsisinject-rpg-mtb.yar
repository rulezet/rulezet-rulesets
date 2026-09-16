rule Trojan_Win32_NSISInject_RPG_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {55 72 62 61 6e 69 74 65 74 65 6e 73 } 		$a_81_1 = {47 67 65 6c 65 64 65 72 6e 65 2e 41 76 6c 32 34 30 } 		$a_81_2 = {53 6f 66 74 77 61 72 65 5c 43 6f 65 72 63 69 76 65 5c 4c 6f 72 61 72 69 75 73 5c 48 6f 69 73 74 65 64 } 		$a_81_3 = {42 69 6f 74 65 6b 6e 69 6b 65 72 65 72 6e 65 73 2e 4a 75 6e } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}