rule Trojan_Win32_RedLineStealer_PB_MTB_3{
	meta:
		description = "Trojan:Win32/RedLineStealer.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 05 89 45 0c 8b 45 ec 01 45 0c 8b 45 e8 83 25 ?? ?? ?? ?? ?? 03 c8 8d 04 3b 33 c8 31 4d 0c 8b 45 0c 01 05 44 7e b4 00 2b 75 0c } 		$a_03_1 = {8b 44 24 10 03 44 24 18 89 44 24 1c 8b 44 24 18 c1 e8 ?? 89 44 24 14 8b 44 24 14 33 74 24 1c 03 c3 33 c6 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 14 75 68 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}