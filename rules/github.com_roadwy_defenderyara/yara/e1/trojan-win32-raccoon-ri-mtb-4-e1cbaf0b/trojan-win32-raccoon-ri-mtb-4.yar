rule Trojan_Win32_Raccoon_RI_MTB_4{
	meta:
		description = "Trojan:Win32/Raccoon.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c2 08 00 81 01 e1 34 ef c6 c3 } 		$a_03_1 = {d3 e8 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 [0-70] 81 6d ?? 36 dd 96 53 81 45 ?? 3a dd 96 53 8b 45 ?? 8b 4d ?? d3 e0 [0-30] d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 45 [0-09] 31 45 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}