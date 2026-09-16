rule Trojan_BAT_FormBook_AAF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {26 1a 8d 14 00 00 01 25 16 11 04 a2 25 17 7e 14 00 00 0a a2 25 18 07 a2 25 19 17 8c 04 00 00 01 a2 13 06 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}