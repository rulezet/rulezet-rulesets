rule Trojan_Win32_DomainTrustDiscovery_MK_2{
	meta:
		description = "Trojan:Win32/DomainTrustDiscovery.MK,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 00 62 00 5f 00 } 		$a_00_1 = {5f 00 62 00 73 00 20 00 3e 00 6e 00 75 00 6c 00 } 		$a_00_2 = {6e 00 6c 00 74 00 65 00 73 00 74 00 2e 00 65 00 78 00 65 00 20 00 2f 00 64 00 6f 00 6d 00 61 00 69 00 6e 00 5f 00 74 00 72 00 75 00 73 00 74 00 73 00 20 00 31 00 3e 00 20 00 6e 00 75 00 6c 00 20 00 20 00 26 00 20 00 65 00 78 00 69 00 74 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}