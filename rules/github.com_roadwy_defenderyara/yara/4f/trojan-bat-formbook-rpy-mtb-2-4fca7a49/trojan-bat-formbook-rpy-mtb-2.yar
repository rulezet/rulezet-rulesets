rule Trojan_BAT_FormBook_RPY_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 13 0d 11 0d 11 0c 59 20 00 01 00 00 58 20 00 01 00 00 5d 13 0e 07 11 0b 11 08 6a 5d d4 11 0e } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}