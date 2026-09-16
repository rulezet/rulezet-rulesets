rule Trojan_BAT_FormBook_RPY_MTB_6{
	meta:
		description = "Trojan:BAT/FormBook.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {1f 16 5d 91 13 05 07 11 04 91 11 05 61 13 06 11 04 17 58 07 8e 69 5d 13 07 07 11 07 91 13 08 11 06 11 08 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 09 07 11 04 11 09 d2 9c 00 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 0a 11 0a 2d a1 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}