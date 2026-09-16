rule Trojan_Win32_NSISInject_RPQ_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {43 6f 6e 67 69 69 } 		$a_81_1 = {4e 65 63 6b 74 69 65 6c 65 73 73 } 		$a_81_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 61 66 6d 61 67 72 69 6e 67 65 72 6e 65 } 		$a_81_3 = {41 70 70 65 6c 6d 75 6c 69 67 68 65 64 65 72 2e 4f 7a 6f } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}