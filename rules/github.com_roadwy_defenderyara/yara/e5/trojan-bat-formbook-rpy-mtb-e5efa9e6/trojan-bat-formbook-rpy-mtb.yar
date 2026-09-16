rule Trojan_BAT_FormBook_RPY_MTB{
	meta:
		description = "Trojan:BAT/FormBook.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 09 91 11 06 58 13 0c 07 11 08 11 0a 11 0b 61 11 0c 11 06 5d 59 d2 9c 00 11 05 17 58 13 05 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}