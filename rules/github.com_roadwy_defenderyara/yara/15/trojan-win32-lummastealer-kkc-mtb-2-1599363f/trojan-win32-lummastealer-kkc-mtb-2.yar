rule Trojan_Win32_LummaStealer_KKC_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.KKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c2 81 f2 ?? ?? ?? ?? 89 14 24 8b 14 24 8b 34 24 21 ce 01 ca 29 f2 89 54 24 0c 8b 54 24 0c 8b 34 24 21 ce 29 f2 89 54 24 08 8b 4c 24 08 80 c1 ?? ?? ?? ?? ?? 40 83 f8 } 	condition:
		((#a_03_0  & 1)*20) >=20
 
}