rule Trojan_BAT_FormBook_RPZ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 09 5d 13 05 06 11 04 8e 69 5d 13 08 07 11 05 91 11 04 11 08 91 61 d2 13 09 11 09 07 06 17 58 09 5d 91 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}