rule Trojan_BAT_FormBook_RPY_MTB_4{
	meta:
		description = "Trojan:BAT/FormBook.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 11 06 09 5d 13 07 11 06 08 8e 69 5d 13 08 07 11 07 91 08 11 08 91 61 d2 13 09 11 09 07 11 06 17 58 09 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}