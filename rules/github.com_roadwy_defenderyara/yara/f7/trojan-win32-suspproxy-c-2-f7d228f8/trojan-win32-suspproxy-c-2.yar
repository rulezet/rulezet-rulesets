rule Trojan_Win32_SuspProxy_C_2{
	meta:
		description = "Trojan:Win32/SuspProxy.C,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {63 6f 6e 68 6f 73 74 2e 65 78 65 } 		$a_80_1 = {6e 6f 74 65 70 61 64 2e 65 78 65 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}