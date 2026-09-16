rule Trojan_Win32_Redline_GNH_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.GNH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 04 33 d3 ee 8b 4c 24 ?? 89 44 24 ?? 8d 44 24 ?? 89 74 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}