rule Trojan_Win32_SuspProxy_I_3{
	meta:
		description = "Trojan:Win32/SuspProxy.I,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 } 		$a_80_1 = {7a 69 70 66 6c 64 72 2c 52 6f 75 74 65 54 68 65 43 61 6c 6c } 		$a_80_2 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } 		$a_80_3 = {61 64 6f 62 65 2e 65 78 65 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}