rule Trojan_Win32_SuspProxy_D_2{
	meta:
		description = "Trojan:Win32/SuspProxy.D,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 } 		$a_80_1 = {25 50 55 42 4c 49 43 46 49 4c 45 53 25 } 		$a_80_2 = {6d 73 68 74 6d 6c } 		$a_80_3 = {52 75 6e 48 54 4d 4c 41 70 70 6c 69 63 61 74 69 6f 6e } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}