rule Trojan_Win64_DllHijack_GPKG_MTB_2{
	meta:
		description = "Trojan:Win64/DllHijack.GPKG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {75 2d ff 15 ?? ?? ?? 00 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 ?? c7 44 24 ?? 2e 64 6c 6c c6 44 24 ?? 00 48 8d 4c 24 ?? ff 15 ?? ?? ?? 00 b8 01 00 00 00 48 83 c4 } 		$a_01_1 = {44 69 73 61 62 6c 65 54 68 72 65 61 64 4c 69 62 72 61 72 79 43 61 6c 6c 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}