rule Trojan_Win32_Ursnif_S_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 17 13 d8 89 35 ?? ?? 43 00 8b 44 24 1c 0f b7 c8 8b c1 89 1d ?? ?? 43 00 2b 05 ?? ?? 43 00 05 1a b9 00 00 89 54 24 18 a3 ?? ?? 43 00 8d 81 1b ff ff ff 03 c5 3d 2a 0e 00 00 7c 1a 6b c1 4d 2b c5 99 8b da 8b f0 8b 54 24 18 89 35 ?? ?? 43 00 89 1d ?? ?? 43 00 6b 6c 24 10 4d 81 c2 d8 e9 eb 01 6a 00 } 		$a_02_1 = {2b 44 24 28 1b d7 03 d8 89 1d ?? ?? 43 00 13 ea 89 2d ?? ?? 43 00 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}