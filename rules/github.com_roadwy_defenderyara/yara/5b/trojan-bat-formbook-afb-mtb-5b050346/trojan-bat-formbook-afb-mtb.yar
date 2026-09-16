rule Trojan_BAT_FormBook_AFB_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0c 07 11 0b 91 59 11 0d 58 11 0d 5d 13 0e 07 11 09 11 0e d2 9c 11 11 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}