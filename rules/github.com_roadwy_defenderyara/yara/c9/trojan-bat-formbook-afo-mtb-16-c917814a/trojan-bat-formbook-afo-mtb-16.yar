rule Trojan_BAT_FormBook_AFO_MTB_16{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 0a 2b 19 00 02 06 94 07 fe 02 0c 08 2c 09 00 02 06 94 0b 03 06 54 00 00 06 17 58 0a 06 02 8e 69 fe 04 0d 09 2d } 		$a_01_1 = {50 00 61 00 6c 00 65 00 6f 00 6c 00 69 00 74 00 68 00 69 00 63 00 20 00 43 00 6f 00 6f 00 70 00 65 00 72 00 61 00 74 00 69 00 6f 00 6e 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}