rule Trojan_Win32_Redline_GNT_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c7 89 45 ?? 8b 45 ?? c1 e8 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 ?? 89 5d ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 33 45 ?? 2b f0 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}