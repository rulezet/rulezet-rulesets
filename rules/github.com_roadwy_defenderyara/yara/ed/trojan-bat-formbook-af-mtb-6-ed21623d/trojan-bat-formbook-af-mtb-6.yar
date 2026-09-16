rule Trojan_BAT_FormBook_AF_MTB_6{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 07 13 07 16 13 06 2b 2f 11 07 11 06 9a 0c 08 6f ?? 00 00 0a 28 ?? 00 00 06 26 7e 0e 00 00 04 2c 02 de 1c } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}