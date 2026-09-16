rule Trojan_Win32_Predator_R_MTB_2{
	meta:
		description = "Trojan:Win32/Predator.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {46 3b f0 72 90 0a 66 00 3d 80 04 00 00 75 ?? 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff } 		$a_02_1 = {8a c1 24 fc c0 e0 04 0a 44 33 01 8a d9 80 e1 f0 02 c9 02 c9 0a 0c 2e c0 e3 06 0a 5c 2e 02 88 0c 3a 42 88 04 3a 42 88 1c 3a 83 c6 04 42 3b 35 ?? ?? ?? ?? 72 bb 90 09 10 00 8b 1d ?? ?? ?? ?? 8a 4c 33 03 8b 2d } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*2) >=3
 
}