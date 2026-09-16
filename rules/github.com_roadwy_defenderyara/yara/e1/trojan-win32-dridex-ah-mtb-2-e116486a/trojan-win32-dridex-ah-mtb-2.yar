rule Trojan_Win32_Dridex_AH_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {8d 14 01 8d 7c 17 17 8b d0 2b d1 03 d3 8d 0c 12 81 c6 94 3c 0a 01 8b d7 89 75 00 2b d1 } 		$a_02_1 = {8b c1 6b c9 05 2b c6 83 c0 2c 03 ca 0f b7 15 ?? ?? ?? ?? 8b 75 00 2b d7 03 15 ?? ?? ?? ?? 8d 9c 01 d0 55 00 00 8b fa 8b d3 6b d2 05 03 d1 } 	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}