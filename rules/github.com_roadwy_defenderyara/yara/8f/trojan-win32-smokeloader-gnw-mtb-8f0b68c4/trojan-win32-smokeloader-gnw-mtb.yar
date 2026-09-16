rule Trojan_Win32_Smokeloader_GNW_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GNW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 14 c1 e8 05 03 44 24 34 81 3d ?? ?? ?? ?? 79 09 00 00 c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 20 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}