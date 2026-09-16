rule Trojan_Win32_Smokeloader_GNW_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GNW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 04 3e 89 45 ?? 8b c7 d3 e8 8b 4d ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 31 45 ?? 81 3d } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}