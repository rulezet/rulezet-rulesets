rule Trojan_BAT_FormBook_RPY_MTB_5{
	meta:
		description = "Trojan:BAT/FormBook.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 13 0b 08 11 0b 91 11 08 58 13 0c 08 11 0a 91 13 0d 09 11 04 1f 16 5d 91 13 0e 11 0d 11 0e 61 13 0f 11 0f 11 0c 59 13 10 08 11 0a 11 10 11 08 5d d2 9c 11 04 17 58 13 04 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}