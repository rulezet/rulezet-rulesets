rule Trojan_BAT_Formbook_EAOG_MTB{
	meta:
		description = "Trojan:BAT/Formbook.EAOG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 07 1d 63 61 0a 11 21 20 81 7e 5b be 5a 20 e3 38 4d 58 61 38 66 fe ff ff 11 0d 18 fe 02 13 1a 11 1a 2d 08 20 a9 9e 7d 2f 25 2b 06 20 bb 24 81 41 25 26 38 47 fe ff ff 19 13 0d 11 21 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}