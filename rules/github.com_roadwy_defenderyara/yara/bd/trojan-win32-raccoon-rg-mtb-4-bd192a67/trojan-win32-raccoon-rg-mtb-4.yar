rule Trojan_Win32_Raccoon_RG_MTB_4{
	meta:
		description = "Trojan:Win32/Raccoon.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 00 e1 34 ef c6 c3 01 08 c3 } 		$a_03_1 = {36 dd 96 53 81 45 ?? 38 dd 96 53 8b 4d ?? 8b c6 d3 e0 [0-20] 8b c6 d3 e8 89 55 ?? 89 3d ?? ?? ?? ?? 03 45 ?? 33 c2 31 45 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}