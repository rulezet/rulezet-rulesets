rule Trojan_BAT_FormBook_AFA_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.AFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 16 16 fe 01 13 17 11 17 2c 03 17 13 16 09 11 14 07 11 14 91 11 04 11 15 95 61 d2 9c 00 11 14 17 58 13 14 11 14 07 8e 69 fe 04 13 18 } 		$a_03_1 = {16 0a 16 0b 2b 11 00 02 07 06 03 04 28 ?? 00 00 06 0a 07 17 58 0b 00 07 20 00 01 00 00 fe 05 0c } 	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}