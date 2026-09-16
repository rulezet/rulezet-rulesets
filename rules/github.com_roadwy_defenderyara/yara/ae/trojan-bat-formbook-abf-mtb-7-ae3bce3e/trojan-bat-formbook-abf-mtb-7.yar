rule Trojan_BAT_FormBook_ABF_MTB_7{
	meta:
		description = "Trojan:BAT/FormBook.ABF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0c 00 07 0e 04 6f ?? 00 00 0a 61 19 5f 17 fe 01 13 0a 11 0a 2c 09 00 08 07 1f 1f 5f 58 0c 00 00 de 08 00 08 1f 0a 61 0c } 		$a_03_1 = {07 17 62 11 0b 19 58 61 0b 02 09 11 0b 6f ?? 00 00 0a 13 0c 04 03 6f ?? 00 00 0a 59 13 0d 11 0d 13 0f 11 0f } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}