rule Trojan_Win32_Vidar_AB_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c8 c1 e9 05 03 4c 24 2c 8b d0 c1 e2 04 03 54 24 28 03 c7 33 ca 33 c8 2b f1 8b ce c1 e1 04 c7 05 ?? ?? ?? ?? 00 00 00 00 89 4c 24 14 8b 44 24 30 01 44 24 14 81 3d ?? ?? ?? ?? be 01 00 00 8d 1c 37 75 11 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}