rule Trojan_Win32_Smokeloader_GXN_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GXN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 04 2a 89 44 24 ?? 8b 44 24 ?? c1 e8 ?? 89 44 24 ?? 8b 4c 24 ?? 8b 44 24 ?? 33 4c 24 ?? 03 44 24 ?? 33 c1 c7 05 ?? ?? ?? ?? ee 3d ea f4 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}