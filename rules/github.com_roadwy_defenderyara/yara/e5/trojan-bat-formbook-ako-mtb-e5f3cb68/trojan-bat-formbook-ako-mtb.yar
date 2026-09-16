rule Trojan_BAT_FormBook_AKO_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AKO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 15 12 15 28 ?? 00 00 0a 16 61 d2 13 16 12 15 28 ?? 00 00 0a 16 61 d2 13 17 12 15 28 ?? 00 00 0a 16 61 d2 13 18 19 8d ?? 00 00 01 25 16 11 16 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}