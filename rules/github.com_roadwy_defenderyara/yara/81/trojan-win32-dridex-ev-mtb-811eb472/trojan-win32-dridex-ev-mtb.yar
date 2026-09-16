rule Trojan_Win32_Dridex_EV_MTB{
	meta:
		description = "Trojan:Win32/Dridex.EV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 10 8a d1 83 c0 04 02 d2 03 c6 66 a3 ?? ?? ?? ?? b0 2d 2a c2 ba 30 0e 00 00 02 d8 } 		$a_02_1 = {0f b7 c6 2b d0 83 c2 16 0f af d0 8b 07 69 d2 81 ea 00 00 89 15 ?? ?? ?? ?? 05 10 b3 07 01 89 07 83 c7 04 } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}