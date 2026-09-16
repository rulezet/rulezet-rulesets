rule Trojan_Win32_Dridex_AH_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8d 04 dd 00 00 00 00 2b c3 03 c0 03 c0 0f b7 c0 8a 0d ?? ?? ?? ?? 2a c8 80 e9 4c 02 d1 66 0f b6 c2 66 03 c3 66 83 c0 09 0f b7 c8 8b 06 } 		$a_00_1 = {02 c1 2c 61 02 d0 83 c6 04 83 ef 01 } 	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}