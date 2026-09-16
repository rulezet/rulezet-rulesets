rule Trojan_Win32_SuspDiscovery_D{
	meta:
		description = "Trojan:Win32/SuspDiscovery.D,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {73 63 68 74 61 73 6b 73 2e 65 78 65 20 2f 63 72 65 61 74 65 20 2f 53 54 } 		$a_80_1 = {2f 53 43 20 4d 49 4e 55 54 45 20 2f 4d 4f } 		$a_80_2 = {73 76 63 68 6f 73 74 2e 65 78 65 } 		$a_80_3 = {2f 54 4e 20 53 74 6f 72 53 79 6e 63 53 76 63 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}