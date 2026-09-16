rule Trojan_BAT_FormBook_AKK_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 05 00 11 04 02 6f ?? 00 00 0a fe 04 16 fe 01 13 0f 11 0f 2c 05 38 ?? 01 00 00 11 05 02 6f ?? 00 00 0a fe 04 16 fe 01 13 10 11 10 2c 05 } 		$a_03_1 = {11 04 11 05 6f ?? 00 00 0a 13 07 12 07 28 ?? 00 00 0a 13 08 12 07 28 ?? 00 00 0a 13 09 12 07 28 ?? 00 00 0a 13 0a 03 13 12 11 12 2c 1d 00 11 08 28 ?? 00 00 06 13 08 11 09 28 ?? 00 00 06 13 09 11 0a 28 ?? 00 00 06 13 0a 00 11 08 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}