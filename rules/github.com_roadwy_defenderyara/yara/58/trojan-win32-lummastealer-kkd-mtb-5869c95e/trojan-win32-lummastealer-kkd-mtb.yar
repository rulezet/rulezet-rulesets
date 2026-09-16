rule Trojan_Win32_LummaStealer_KKD_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.KKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 4c 04 04 89 c2 81 f2 ?? ?? ?? ?? 89 14 24 8b 14 24 01 ca 8b 34 24 21 ce [0-14] 24 0c 8b 54 24 0c 8b 34 24 21 ce 29 f2 89 54 24 08 8b 4c 24 08 [0-14] 88 4c 04 04 40 83 f8 04 } 	condition:
		((#a_03_0  & 1)*20) >=20
 
}