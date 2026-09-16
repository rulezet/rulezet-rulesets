rule Trojan_Win32_Raccrypt_GD_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 84 32 36 23 01 00 88 04 31 81 c4 ?? ?? 00 00 c3 } 		$a_02_1 = {c1 ea 05 03 d5 c7 05 ?? ?? ?? ?? b4 02 d7 cb c7 05 ?? ?? ?? ?? ff ff ff ff 89 54 24 ?? 8b 44 24 ?? 31 44 24 ?? 2b 74 24 ?? 8d 44 24 ?? e8 } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}