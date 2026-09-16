rule Trojan_BAT_FormBook_AKO_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.AKO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 5f 11 05 7e ?? 00 00 04 1f 6e 7e ?? 00 00 04 1f 6e 91 03 5f 20 94 00 00 00 5f 9c 5f 11 06 5f 11 07 5f 13 08 16 13 0b } 		$a_03_1 = {11 0d 20 a0 00 00 00 91 1f 4e 59 2b ec 06 74 ?? 00 00 02 7b ?? 00 00 04 8e 16 fe 03 2b 01 17 13 05 06 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}