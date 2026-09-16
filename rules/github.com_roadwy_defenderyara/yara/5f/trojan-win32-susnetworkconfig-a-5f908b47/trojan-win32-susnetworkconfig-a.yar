rule Trojan_Win32_SusNetworkConfig_A{
	meta:
		description = "Trojan:Win32/SusNetworkConfig.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_80_0 = {63 75 72 6c 2e 65 78 65 20 } 		$a_00_1 = {2e 00 63 00 6f 00 6d 00 } 		$a_00_2 = {39 00 34 00 35 00 33 00 65 00 38 00 38 00 31 00 2d 00 32 00 36 00 61 00 38 00 2d 00 34 00 39 00 37 00 33 00 2d 00 62 00 61 00 32 00 65 00 2d 00 37 00 36 00 32 00 36 00 39 00 65 00 39 00 30 00 31 00 64 00 30 00 77 00 } 	condition:
		((#a_80_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*-1) >=2
 
}