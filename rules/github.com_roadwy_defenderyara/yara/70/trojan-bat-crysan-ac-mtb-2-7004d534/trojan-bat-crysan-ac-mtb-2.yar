rule Trojan_BAT_Crysan_AC_MTB_2{
	meta:
		description = "Trojan:BAT/Crysan.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {a2 25 17 7e ?? 00 00 0a a2 25 18 09 a2 25 19 17 8c ?? 00 00 01 a2 13 04 14 13 05 07 28 ?? 00 00 0a 72 ?? 02 00 70 6f ?? 00 00 0a 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}