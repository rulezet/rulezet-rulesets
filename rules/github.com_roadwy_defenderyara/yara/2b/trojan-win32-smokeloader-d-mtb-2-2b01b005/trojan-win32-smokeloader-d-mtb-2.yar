rule Trojan_Win32_SmokeLoader_D_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 84 38 4b 13 01 00 8b 0d ?? ?? ?? ?? 88 04 39 75 06 ff 15 ?? ?? ?? ?? 47 3b 3d ?? ?? ?? ?? 72 d0 } 		$a_03_1 = {d3 ef 89 45 e0 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 7d e4 8b 45 e0 31 45 fc 33 7d fc } 		$a_03_2 = {31 7d fc 8b 45 fc 29 45 f4 81 c3 47 86 c8 61 ff 4d e8 0f 85 ?? fe ff ff } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}