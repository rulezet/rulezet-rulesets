rule Trojan_BAT_FormBook_AFO_MTB_15{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 0d 2b 3f 00 09 02 7b ?? 00 00 04 8e 69 17 59 fe 02 13 04 11 04 2c 04 16 0c 2b 3a 02 7b ?? 00 00 04 09 91 20 80 00 00 00 5f 20 80 00 00 00 fe 01 16 fe 01 13 05 11 05 2c 04 09 0c 2b 18 00 09 17 58 0d 09 06 fe 02 16 fe 01 13 06 11 06 2d b4 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}