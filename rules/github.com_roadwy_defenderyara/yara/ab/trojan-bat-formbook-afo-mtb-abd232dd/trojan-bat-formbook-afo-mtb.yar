rule Trojan_BAT_FormBook_AFO_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0a 2b 1b 02 06 02 06 91 7e 06 00 00 04 06 7e 06 00 00 04 8e 69 5d 91 61 d2 9c 06 17 58 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}