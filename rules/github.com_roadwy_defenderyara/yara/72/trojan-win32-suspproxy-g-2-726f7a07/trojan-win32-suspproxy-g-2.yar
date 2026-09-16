rule Trojan_Win32_SuspProxy_G_2{
	meta:
		description = "Trojan:Win32/SuspProxy.G,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 63 6f 70 79 } 		$a_80_1 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 } 		$a_80_2 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } 		$a_80_3 = {61 64 6f 62 65 2e 65 78 65 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=2
 
}