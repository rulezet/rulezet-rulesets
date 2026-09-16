rule Trojan_Win32_SuspProxy_MK_2{
	meta:
		description = "Trojan:Win32/SuspProxy.MK,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {63 73 63 72 69 70 74 2e 65 78 65 20 } 		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } 		$a_80_2 = {73 69 6c 65 6e 63 65 2e 76 62 73 } 		$a_00_3 = {2e 00 65 00 78 00 65 00 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}