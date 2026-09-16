rule Trojan_Win32_SuspProxy_B_2{
	meta:
		description = "Trojan:Win32/SuspProxy.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 } 		$a_80_1 = {61 64 76 70 61 63 6b 2e 64 6c 6c } 		$a_80_2 = {66 6f 6f 62 61 72 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}