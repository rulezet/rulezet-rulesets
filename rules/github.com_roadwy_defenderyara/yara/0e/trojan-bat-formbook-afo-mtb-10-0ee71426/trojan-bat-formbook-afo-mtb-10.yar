rule Trojan_BAT_FormBook_AFO_MTB_10{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 11 04 09 8e 69 5d 09 8e 69 58 09 8e 69 5d 91 13 05 11 04 17 58 08 5d 08 58 08 5d 13 06 07 11 06 08 5d 08 58 08 5d 91 13 07 07 11 04 08 5d 08 58 08 5d 91 11 05 61 11 07 59 20 00 02 00 00 58 20 00 01 00 00 5d 20 00 04 00 00 58 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}