rule Trojan_Win32_LummaStealer_KK_MTB_3{
	meta:
		description = "Trojan:Win32/LummaStealer.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {c8 09 00 00 89 ?? 81 ?? fe ff ff 7f 09 ?? 89 ?? 83 e7 01 f7 df 81 e7 df b0 08 99 33 bc ?? f8 0f 00 00 d1 ?? 31 ?? 89 bc ?? 84 13 00 00 83 c0 04 } 	condition:
		((#a_03_0  & 1)*20) >=20
 
}