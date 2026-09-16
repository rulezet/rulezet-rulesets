rule Trojan_BAT_NJRat_RPZ_MTB{
	meta:
		description = "Trojan:BAT/NJRat.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 00 06 1f 0c 58 06 1f 0c 58 4a 17 d6 54 06 1f 10 58 06 1f 0c 58 4a 11 04 8e 69 fe 04 52 06 1f 10 58 46 2d ad } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}