rule Trojan_BAT_FormBook_RPX_MTB{
	meta:
		description = "Trojan:BAT/FormBook.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 11 05 07 8e 69 5d 13 06 07 11 06 91 08 11 05 1f 16 5d 91 61 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}