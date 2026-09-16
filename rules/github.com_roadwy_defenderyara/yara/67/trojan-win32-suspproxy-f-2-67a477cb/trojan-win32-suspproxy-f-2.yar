rule Trojan_Win32_SuspProxy_F_2{
	meta:
		description = "Trojan:Win32/SuspProxy.F,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 } 		$a_80_1 = {74 69 6d 65 6f 75 74 } 		$a_80_2 = {74 61 73 6b 6c 69 73 74 20 2f 73 76 63 } 		$a_80_3 = {66 69 6e 64 73 74 72 20 2f 69 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=2
 
}