rule Trojan_BAT_FormBook_AF_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 72 4d 00 00 70 12 00 73 2c 00 00 0a 80 03 00 00 04 06 3a 06 00 00 00 17 28 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}