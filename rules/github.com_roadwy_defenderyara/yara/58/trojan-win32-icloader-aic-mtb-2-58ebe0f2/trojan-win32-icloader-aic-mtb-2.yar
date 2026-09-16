rule Trojan_Win32_ICLoader_AIC_MTB_2{
	meta:
		description = "Trojan:Win32/ICLoader.AIC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {80 c9 10 c0 e9 03 81 e1 ff 00 00 00 89 4c 24 00 db 44 24 00 dc 3d c8 49 8a 00 dc 05 58 10 8a 00 dd 1d 38 4a 8a 00 ff 15 ?? ?? ?? ?? 25 ff 00 00 00 83 f8 06 0f 93 c2 83 f8 06 } 		$a_03_1 = {56 57 68 24 4b 8a 00 68 48 48 8a 00 ff 15 ?? ?? ?? ?? a1 64 10 8a 00 8b 35 f0 e2 89 00 50 ff d6 8b 3d f4 e2 89 00 68 b8 10 8a 00 50 ff d7 8b 0d 64 10 8a 00 a3 78 49 8a 00 51 ff d6 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}