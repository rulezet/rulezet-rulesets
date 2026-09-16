rule Trojan_Win32_LummaStealer_KKA_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.KKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 8b 4c 24 10 0f b6 0c 01 35 ?? ?? ?? ?? 89 44 24 04 8b 44 24 04 [0-03] 54 24 } 	condition:
		((#a_03_0  & 1)*20) >=20
 
}