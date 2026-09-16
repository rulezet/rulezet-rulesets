rule Trojan_BAT_FormBook_ABF_MTB_9{
	meta:
		description = "Trojan:BAT/FormBook.ABF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 06 07 6f ?? 00 00 0a 0c 04 03 6f ?? 00 00 0a 59 0d 09 19 fe 04 16 fe 01 13 04 11 04 2c 2f 00 03 19 8d ?? 00 00 01 25 16 12 02 28 ?? 00 00 0a 9c 25 17 12 02 28 ?? 00 00 0a 9c 25 18 12 02 28 ?? 00 00 0a 9c 6f } 		$a_01_1 = {49 00 67 00 6e 00 69 00 74 00 65 00 46 00 69 00 74 00 6e 00 65 00 73 00 73 00 54 00 72 00 61 00 63 00 6b 00 65 00 72 00 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}