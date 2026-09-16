rule Trojan_Win32_Redline_GJV_MTB{
	meta:
		description = "Trojan:Win32/Redline.GJV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d6 d3 ea 03 c6 89 44 24 ?? 8b cb 8d 44 24 ?? 89 54 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}