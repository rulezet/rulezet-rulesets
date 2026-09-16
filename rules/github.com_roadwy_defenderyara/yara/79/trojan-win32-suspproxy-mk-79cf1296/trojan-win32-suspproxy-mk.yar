rule Trojan_Win32_SuspProxy_MK{
	meta:
		description = "Trojan:Win32/SuspProxy.MK,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 } 		$a_80_1 = {75 72 6c 2e 64 6c 6c } 		$a_80_2 = {54 65 6c 6e 65 74 50 72 6f 74 6f 63 6f 6c 48 61 6e 64 6c 65 72 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}