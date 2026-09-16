rule Trojan_BAT_FormBook_ABF_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.ABF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 6f b7 00 00 0a 6f ?? 00 00 0a 13 07 19 8d ?? 00 00 01 25 16 12 07 28 88 00 00 0a 9c 25 17 12 07 28 8a 00 00 0a 9c 25 18 12 07 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}