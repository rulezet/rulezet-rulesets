rule Trojan_Win32_SuspProxy_H_2{
	meta:
		description = "Trojan:Win32/SuspProxy.H,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 } 		$a_80_1 = {75 72 6c 2c 4f 70 65 6e 55 52 4c 20 66 69 6c 65 3a } 		$a_80_2 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } 		$a_80_3 = {61 64 6f 62 65 2e 65 78 65 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}