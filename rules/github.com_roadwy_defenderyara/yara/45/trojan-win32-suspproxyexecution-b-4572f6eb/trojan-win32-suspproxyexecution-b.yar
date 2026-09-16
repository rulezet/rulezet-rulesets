rule Trojan_Win32_SuspProxyExecution_B{
	meta:
		description = "Trojan:Win32/SuspProxyExecution.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {26 20 63 6d 73 74 70 2e 65 78 65 20 2f 73 } 		$a_80_1 = {5f 63 6d 73 74 70 2e 74 78 74 } 		$a_80_2 = {5f 63 6d 73 74 70 2e 69 6e 69 } 	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}