rule Trojan_BAT_FormBook_AFM_MTB_11{
	meta:
		description = "Trojan:BAT/FormBook.AFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 09 18 62 11 04 17 63 59 61 0c 08 11 04 5f 09 1f 3f 61 60 0d 09 1a 5d 2c 06 11 04 19 59 2b 04 11 04 18 58 13 04 00 11 0c 17 58 13 0c 11 0c 1f 4b fe 04 13 0d 11 0d 2d c6 } 		$a_01_1 = {50 00 65 00 72 00 73 00 6f 00 6e 00 6e 00 65 00 6c 00 54 00 72 00 61 00 63 00 6b 00 69 00 6e 00 67 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}