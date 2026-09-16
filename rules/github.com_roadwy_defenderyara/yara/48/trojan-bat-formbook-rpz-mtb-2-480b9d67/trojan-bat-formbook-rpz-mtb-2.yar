rule Trojan_BAT_FormBook_RPZ_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 11 07 1e 62 08 11 08 6f 57 00 00 0a a5 14 00 00 01 60 13 09 08 11 08 11 09 1f 18 5b d2 8c 14 00 00 01 6f 58 00 00 0a 00 11 09 1f 18 5d 13 07 07 11 05 06 11 07 93 9d 00 11 08 17 59 13 08 11 08 16 fe 04 16 fe 01 13 0a 11 0a 2d b3 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}