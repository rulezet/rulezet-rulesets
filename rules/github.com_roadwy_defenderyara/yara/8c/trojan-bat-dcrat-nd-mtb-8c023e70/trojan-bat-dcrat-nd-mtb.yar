rule Trojan_BAT_DCRat_ND_MTB{
	meta:
		description = "Trojan:BAT/DCRat.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 25 00 00 0a 28 ?? 00 00 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 07 28 ?? 00 00 0a 00 07 } 		$a_03_1 = {72 8d 00 00 70 28 ?? 00 00 0a 00 20 ?? 0d 00 00 28 ?? 00 00 0a 00 28 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*3) >=5
 
}