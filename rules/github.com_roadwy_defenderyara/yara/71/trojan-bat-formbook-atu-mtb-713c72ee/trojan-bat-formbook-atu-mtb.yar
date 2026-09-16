rule Trojan_BAT_FormBook_ATU_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ATU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 05 2b 3c 00 07 11 05 07 8e 69 5d 07 11 05 07 8e 69 5d 91 08 11 05 1f 16 5d 6f ?? ?? ?? 0a 61 07 11 05 17 58 07 8e 69 5d 91 20 00 01 00 00 58 20 00 01 00 00 5d 59 d2 9c 00 11 05 15 58 13 05 11 05 16 fe 04 16 fe 01 13 06 11 06 2d b6 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}