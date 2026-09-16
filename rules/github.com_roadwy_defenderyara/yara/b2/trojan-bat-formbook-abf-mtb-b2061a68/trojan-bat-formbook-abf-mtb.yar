rule Trojan_BAT_FormBook_ABF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 07 2b 15 11 06 11 07 91 13 08 00 11 08 04 61 13 09 00 11 07 17 58 13 07 11 07 11 06 8e 69 32 e3 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}