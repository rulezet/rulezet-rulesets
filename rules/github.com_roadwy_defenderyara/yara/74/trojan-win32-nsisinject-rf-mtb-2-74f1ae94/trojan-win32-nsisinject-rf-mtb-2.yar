rule Trojan_Win32_NSISInject_RF_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 67 67 72 65 67 61 74 66 75 6e 6b 74 69 6f 6e 65 72 6e 65 5c 53 75 62 74 65 78 74 2e 49 6e 74 } 		$a_01_1 = {4d 75 6c 74 69 6c 61 6d 69 6e 61 74 65 64 5c 57 61 72 6c 6f 63 6b 72 79 2e 69 6e 69 } 		$a_01_2 = {50 69 74 66 61 6c 6c 73 5c 4e 69 6b 6b 65 64 65 2e 69 6e 69 } 		$a_01_3 = {42 65 76 69 64 73 74 68 65 64 65 72 73 5c 55 6e 72 65 64 5c 54 68 69 65 6c 6f 2e 6c 6e 6b } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}