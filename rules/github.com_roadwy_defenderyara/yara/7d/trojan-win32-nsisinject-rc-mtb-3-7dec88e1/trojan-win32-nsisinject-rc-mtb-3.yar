rule Trojan_Win32_NSISInject_RC_MTB_3{
	meta:
		description = "Trojan:Win32/NSISInject.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {55 6e 64 65 72 66 6f 72 73 74 61 61 65 74 2e 69 6e 69 } 		$a_01_1 = {54 76 72 73 74 69 6c 6c 65 64 65 2e 69 6e 69 } 		$a_01_2 = {6d 61 6a 6f 72 69 73 65 72 69 6e 67 65 6e 73 2e 4e 79 6e } 		$a_01_3 = {4d 65 74 74 65 73 2e 53 69 67 } 		$a_01_4 = {54 75 73 69 6e 64 65 74 73 2e 6c 6e 6b } 		$a_01_5 = {41 69 6c 75 72 6f 6d 61 6e 69 61 2e 4e 65 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}