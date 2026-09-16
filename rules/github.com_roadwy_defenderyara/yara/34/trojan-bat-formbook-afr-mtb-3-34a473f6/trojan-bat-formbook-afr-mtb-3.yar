rule Trojan_BAT_FormBook_AFR_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.AFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 6a 00 07 11 04 93 13 05 11 05 7e 40 00 00 04 8e 69 2f 0d 7e 40 00 00 04 11 05 93 16 fe 01 2b 01 17 13 06 11 06 2c 08 00 06 17 58 0a 00 2b 35 00 06 16 fe 02 13 07 11 07 2c 11 00 03 07 11 04 06 59 06 6f ?? ?? ?? 0a 26 16 0a 00 03 1f 5c } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}