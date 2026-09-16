rule Trojan_Win32_Smokeloader_GY_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d0 d3 e2 8d 0c 07 c1 e8 ?? 89 4c 24 18 03 54 24 38 89 44 24 14 89 54 24 10 8b 44 24 3c 01 44 24 14 8b 54 24 14 33 54 24 18 8b 44 24 10 33 c2 2b f0 81 c7 47 86 c8 61 83 ed ?? 89 44 24 10 89 1d ?? ?? ?? ?? 89 74 24 2c 89 7c 24 28 0f 85 } 		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}