rule Trojan_Win32_Smokeloader_GMK_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 8b 55 ?? d3 e8 03 d7 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 c2 81 3d ?? ?? ?? ?? 03 0b 00 00 89 45 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}