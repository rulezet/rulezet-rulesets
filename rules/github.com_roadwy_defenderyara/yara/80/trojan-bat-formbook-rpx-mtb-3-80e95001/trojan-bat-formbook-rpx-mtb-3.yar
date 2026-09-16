rule Trojan_BAT_FormBook_RPX_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 1f 16 5d 91 61 07 09 17 58 08 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 13 06 07 11 05 11 06 9c 11 04 07 11 05 91 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}