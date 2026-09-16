rule Trojan_Win32_Gatak_DT_dha{
	meta:
		description = "Trojan:Win32/Gatak.DT!dha,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 c7 89 7d ?? 29 f1 8b 45 ?? 8a 5d ?? 80 cb ?? 88 5d ?? 89 4d ?? 8a 5d ?? 38 1c 10 } 	condition:
		((#a_03_0  & 1)*1) >=20
 
}