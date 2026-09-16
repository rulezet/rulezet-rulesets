rule Trojan_Win32_Raccoon_RJ_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c2 08 00 81 01 e1 34 ef c6 c3 } 		$a_03_1 = {8b c3 d3 e8 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 45 cc 89 45 f8 8b 45 e8 31 45 fc 8b 45 fc 31 45 f8 81 3d ?? ?? ?? ?? 6e 0c 00 00 75 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}