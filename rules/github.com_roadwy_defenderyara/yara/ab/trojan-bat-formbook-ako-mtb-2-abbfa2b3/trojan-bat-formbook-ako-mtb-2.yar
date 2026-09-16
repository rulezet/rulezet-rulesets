rule Trojan_BAT_FormBook_AKO_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AKO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 fe 01 13 0b 11 0b 2c 5a 00 03 19 8d ?? 00 00 01 25 16 12 07 28 ?? 00 00 0a 9c 25 17 12 07 28 ?? 00 00 0a 9c 25 18 12 07 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 28 ?? 00 00 0a 13 0d 12 0d 28 ?? 00 00 0a 18 5d 17 fe 01 13 0c 11 0c } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}