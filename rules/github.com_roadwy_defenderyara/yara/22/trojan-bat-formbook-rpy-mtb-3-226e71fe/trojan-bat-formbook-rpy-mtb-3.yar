rule Trojan_BAT_FormBook_RPY_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 06 11 04 17 58 13 07 07 11 04 91 11 05 11 06 91 61 13 08 07 11 04 11 08 07 11 07 07 8e 69 5d 91 59 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}