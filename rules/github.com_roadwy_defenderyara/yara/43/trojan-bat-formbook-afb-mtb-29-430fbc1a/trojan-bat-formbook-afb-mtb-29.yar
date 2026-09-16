rule Trojan_BAT_FormBook_AFB_MTB_29{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 05 06 6f ?? 00 00 0a 0b 03 6f ?? 00 00 0a 0c 04 08 59 0d 09 16 30 03 16 2b 01 17 13 04 08 19 58 04 fe 02 16 fe 01 13 05 11 05 2c 07 11 04 17 fe 01 2b 01 16 13 06 11 06 2c 0f 00 03 07 } 		$a_01_1 = {4d 79 50 61 69 6e 74 2e 45 64 69 74 6f 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}