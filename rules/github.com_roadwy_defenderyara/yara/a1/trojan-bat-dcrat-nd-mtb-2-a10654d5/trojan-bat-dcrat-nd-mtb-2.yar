rule Trojan_BAT_DCRat_ND_MTB_2{
	meta:
		description = "Trojan:BAT/DCRat.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {61 05 61 0a 7e ?? 00 00 04 0c 08 74 ?? 00 00 1b 25 06 93 0b 06 18 58 93 07 61 0b } 		$a_03_1 = {13 04 11 0a 75 ?? 00 00 1b 11 0c 93 13 05 11 0a 74 ?? 00 00 1b 11 0c 17 58 93 11 05 61 13 06 1f 0d } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}