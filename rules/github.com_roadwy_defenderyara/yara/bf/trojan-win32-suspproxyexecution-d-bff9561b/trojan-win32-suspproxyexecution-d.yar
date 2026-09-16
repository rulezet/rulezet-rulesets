rule Trojan_Win32_SuspProxyExecution_D{
	meta:
		description = "Trojan:Win32/SuspProxyExecution.D,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {3e 6e 75 6c 20 26 20 6d 73 69 65 78 65 63 20 2f 69 } 		$a_80_1 = {64 6c 6c 5f 70 61 74 68 3d } 		$a_80_2 = {2f 70 61 73 73 69 76 65 20 26 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}