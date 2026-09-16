rule Trojan_Win32_SuspProxy_E_2{
	meta:
		description = "Trojan:Win32/SuspProxy.E,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {74 74 74 72 61 63 65 72 2e 65 78 65 } 		$a_80_1 = {63 61 6c 63 2e 65 78 65 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}