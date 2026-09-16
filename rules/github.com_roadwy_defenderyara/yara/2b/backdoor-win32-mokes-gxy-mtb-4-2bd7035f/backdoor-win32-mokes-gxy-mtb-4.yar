rule Backdoor_Win32_Mokes_GXY_MTB_4{
	meta:
		description = "Backdoor:Win32/Mokes.GXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e0 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 8b 4d ?? 03 c6 89 45 ?? 8b c6 d3 e8 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 33 c9 89 45 ?? 89 4d ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}