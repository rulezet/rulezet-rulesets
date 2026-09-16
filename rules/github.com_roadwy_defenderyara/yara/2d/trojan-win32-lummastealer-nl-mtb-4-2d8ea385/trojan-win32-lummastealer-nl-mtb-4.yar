rule Trojan_Win32_LummaStealer_NL_MTB_4{
	meta:
		description = "Trojan:Win32/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 24 ?? 8a 4c 24 ?? 84 88 e1 8d ce 00 75 1e 83 7c 24 ?? 00 e9 fa 18 00 00 7f 72 00 0f b7 04 41 23 44 24 ?? eb 02 33 c0 85 c0 75 01 } 		$a_03_1 = {8b 0e 89 48 0c 8b 4d ?? 89 48 04 8b 4d ?? 89 48 08 8b 0d 50 dc c4 00 47 89 58 18 89 48 1c 3b 7d ?? a3 50 dc c4 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}