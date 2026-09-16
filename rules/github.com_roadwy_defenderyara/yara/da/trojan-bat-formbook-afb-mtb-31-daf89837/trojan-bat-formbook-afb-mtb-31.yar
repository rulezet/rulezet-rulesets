rule Trojan_BAT_FormBook_AFB_MTB_31{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5d 08 58 08 5d 13 0b 16 13 17 2b 29 00 11 17 13 19 11 19 13 18 11 18 2c 09 2b 00 11 18 17 2e 08 2b 0c 11 0b 13 0b 2b 06 11 0b 13 0b 2b 00 00 11 17 17 58 13 17 11 17 18 fe 04 } 		$a_01_1 = {16 13 1b 2b 29 00 11 1b 13 1d 11 1d 13 1c 11 1c 2c 09 2b 00 11 1c 17 2e 08 2b 0c 11 13 13 13 2b 06 11 13 13 13 2b 00 00 11 1b 17 58 13 1b 11 1b 18 fe 04 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}