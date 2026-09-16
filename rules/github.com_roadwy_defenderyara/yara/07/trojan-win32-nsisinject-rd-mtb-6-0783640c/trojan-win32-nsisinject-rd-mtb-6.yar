rule Trojan_Win32_NSISInject_RD_MTB_6{
	meta:
		description = "Trojan:Win32/NSISInject.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {47 61 72 64 65 6e 6d 61 6b 69 6e 67 2e 6c 6e 6b } 		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 55 6e 67 64 6f 6d 73 73 65 6b 74 69 6f 6e 65 72 } 		$a_01_2 = {54 61 6b 69 73 74 6f 73 6b 6f 70 73 32 33 30 2e 6c 6e 6b } 		$a_01_3 = {43 68 65 6c 61 74 69 6f 6e 73 2e 69 6e 69 } 		$a_01_4 = {55 6e 69 6e 73 74 61 6c 6c 5c 4f 76 65 72 68 61 6e 67 73 } 		$a_01_5 = {41 70 70 65 74 69 74 6c 73 65 73 74 65 73 2e 64 6c 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}