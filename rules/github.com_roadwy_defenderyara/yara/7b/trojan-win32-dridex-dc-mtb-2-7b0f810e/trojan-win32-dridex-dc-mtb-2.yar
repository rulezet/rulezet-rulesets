rule Trojan_Win32_Dridex_DC_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 55 08 03 32 8b 45 08 89 30 8b 4d f4 81 c1 ?? ?? ?? ?? 8b 55 08 8b 02 2b c1 8b 4d 08 89 01 } 		$a_02_1 = {03 4d c4 8b 15 ?? ?? ?? ?? 2b d1 89 15 ?? ?? ?? ?? b8 73 00 00 00 85 c0 0f 85 23 } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}