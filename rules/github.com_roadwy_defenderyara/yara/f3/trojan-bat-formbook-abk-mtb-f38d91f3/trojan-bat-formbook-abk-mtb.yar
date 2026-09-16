rule Trojan_BAT_FormBook_ABK_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b4 9c 00 2b 0d 00 07 11 04 07 11 04 91 17 da b4 9c 00 11 04 17 d6 13 04 11 04 09 31 ae } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}