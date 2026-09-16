rule Trojan_BAT_FormBook_N_MTB{
	meta:
		description = "Trojan:BAT/FormBook.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 06 08 06 91 11 05 06 11 05 6f 63 01 00 0a 5d 6f 93 01 00 0a 61 d2 9c 06 17 58 0a 06 08 8e 69 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}