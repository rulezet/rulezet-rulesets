rule Trojan_Win32_LummaStealer_KKB_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.KKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 8b 4c 24 ?? 0f b6 0c 01 35 ?? ?? ?? ?? 89 44 24 04 8b 44 24 04 f7 d0 89 ca 21 c2 89 54 24 10 ?? ?? ?? ?? ?? ?? 21 c8 89 44 24 0c 8b 44 24 10 8b 4c 24 0c 09 c8 89 44 24 08 8b 44 24 08 04 ?? 8b 4c 24 ?? 8b 14 24 88 04 11 8b 04 24 } 	condition:
		((#a_03_0  & 1)*20) >=20
 
}