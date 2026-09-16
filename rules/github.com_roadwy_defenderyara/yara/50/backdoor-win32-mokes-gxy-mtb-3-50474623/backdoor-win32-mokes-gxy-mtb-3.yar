rule Backdoor_Win32_Mokes_GXY_MTB_3{
	meta:
		description = "Backdoor:Win32/Mokes.GXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 04 17 89 45 ?? 8b 45 ?? c1 e8 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 55 ?? 8b 4d ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 e8 ?? ?? ?? ?? 8b 4d ?? 33 c8 2b d9 89 4d ?? 8b c3 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}