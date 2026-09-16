rule Trojan_BAT_FormBook_AF_MTB_17{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 16 58 0a 2b 48 06 11 04 5d 13 06 06 11 08 5d 13 0b 07 11 06 91 13 0c 11 05 11 0b 6f ?? ?? ?? 0a 13 0d 07 06 17 58 11 04 5d 91 13 0e 11 0c 11 0d 61 11 0e 59 20 00 01 00 00 58 13 0f 07 11 06 11 0f 20 00 01 00 00 5d d2 9c 06 17 59 0a 06 16 fe 04 16 fe 01 13 10 11 10 2d ab } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}