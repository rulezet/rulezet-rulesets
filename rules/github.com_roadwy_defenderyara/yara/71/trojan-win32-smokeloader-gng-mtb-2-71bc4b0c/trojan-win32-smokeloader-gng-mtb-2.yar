rule Trojan_Win32_Smokeloader_GNG_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GNG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e8 ?? 03 44 24 ?? 03 d3 33 c2 8d 14 0f 33 c2 2b f0 89 44 24 ?? 8b c6 c1 e0 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 03 fe 81 3d } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}