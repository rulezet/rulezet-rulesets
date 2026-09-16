rule Trojan_Win32_Smokeloader_GMQ_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d3 d3 ea 03 c3 89 45 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 ?? 8b 45 ?? 31 45 ?? 33 55 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 55 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}