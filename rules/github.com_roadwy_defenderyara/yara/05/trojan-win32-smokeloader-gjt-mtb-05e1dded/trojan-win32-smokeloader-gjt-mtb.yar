rule Trojan_Win32_Smokeloader_GJT_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c7 33 c1 2b f0 89 44 24 ?? 8b c6 c1 e0 ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8d 3c 2e } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}