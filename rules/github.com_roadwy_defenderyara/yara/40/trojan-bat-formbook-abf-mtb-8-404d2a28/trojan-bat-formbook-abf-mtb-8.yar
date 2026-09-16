rule Trojan_BAT_FormBook_ABF_MTB_8{
	meta:
		description = "Trojan:BAT/FormBook.ABF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 04 6f ?? 00 00 0a 9d 6f ?? 00 00 0a 17 fe 02 0a 06 2c 0a 00 04 17 6f ?? 00 00 0a 00 00 04 6f ?? 00 00 0a 1f 20 fe 01 0b 07 2c 0a 00 04 17 6f } 		$a_03_1 = {16 0d 2b 13 00 02 09 02 09 91 ?? ?? ?? ?? ?? 59 d2 9c 00 09 17 58 0d 09 02 8e 69 fe 04 13 04 11 04 2d e1 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}