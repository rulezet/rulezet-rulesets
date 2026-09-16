rule Trojan_Win32_RedLineStealer_PS_MTB_2{
	meta:
		description = "Trojan:Win32/RedLineStealer.PS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 8b 44 24 ?? 03 44 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 33 90 17 02 01 01 c1 c6 81 3d ?? ?? ?? ?? 16 05 00 00 89 4c 24 ?? 89 44 24 ?? 0f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}