rule Trojan_BAT_nJRat_ANJ_MTB_2{
	meta:
		description = "Trojan:BAT/nJRat.ANJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 64 11 64 16 11 62 a2 00 11 64 17 07 11 61 17 28 ?? 00 00 0a a2 00 11 64 18 11 0c 11 61 17 28 ?? 00 00 0a a2 00 11 64 19 11 17 11 61 17 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}