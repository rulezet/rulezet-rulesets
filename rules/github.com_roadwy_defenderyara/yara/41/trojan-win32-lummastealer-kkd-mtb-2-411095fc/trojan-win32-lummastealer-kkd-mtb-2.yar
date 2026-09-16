rule Trojan_Win32_LummaStealer_KKD_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.KKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 8b 4c 24 18 0f b6 0c 01 35 ?? ?? ?? ?? 89 44 24 04 8b 44 24 04 21 c8 89 44 24 10 8b 44 24 04 21 c8 89 44 24 0c 8b 44 24 04 01 c8 8b 4c 24 10 8b 54 24 0c 01 d1 29 c8 89 44 24 08 8b 44 24 08 04 ?? 8b 4c 24 18 8b 14 24 88 04 11 8b 04 24 2d 55 4e 0a ac 83 c0 ?? 05 55 4e 0a ac 89 04 24 eb 93 } 	condition:
		((#a_03_0  & 1)*20) >=20
 
}