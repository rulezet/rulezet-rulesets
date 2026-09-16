rule Trojan_Win32_RedLineStealer_MC_MTB_2{
	meta:
		description = "Trojan:Win32/RedLineStealer.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {89 1d 44 f1 47 00 8b 4d f4 8b c6 d3 e8 8b 4d e4 c7 05 4c 23 48 00 2e ce 50 91 89 45 f0 8d 45 f0 e8 96 fe ff ff 8b 45 fc 03 c6 50 8b 45 f8 e8 7a fe ff ff 8b 4d f0 33 c8 89 45 f8 2b f9 25 bb 52 c0 5d 8b c7 8d 4d f8 e8 58 fe ff ff 8b 4d d8 8b c7 c1 e8 05 89 45 f0 8d 45 f0 e8 5c fe ff ff 8b 45 fc 8b 4d dc 03 c7 50 8b 45 f8 03 c1 e8 3b fe ff ff 8b 4d f0 89 45 f8 8d 45 f8 e8 2a fe ff ff 2b 75 f8 89 1d 28 e3 47 00 8b 45 e8 29 45 fc ff 4d ec 0f 85 } 		$a_03_1 = {89 55 fc b8 ?? ?? ?? ?? 01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d ?? ?? ?? ?? 72 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}