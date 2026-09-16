rule Trojan_Win32_Raccoon_RM_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e1 34 ef c6 c3 } 		$a_03_1 = {ee 3d ea f4 [0-10] 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 [0-60] 81 6d ?? 36 dd 96 53 81 45 ?? 3a dd 96 53 8b [0-35] 89 45 ?? 8b 45 ?? 01 45 ?? 8b ?? ?? 33 [0-09] 31 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}