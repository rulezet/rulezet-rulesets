rule Trojan_BAT_FormBook_AFO_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0d 16 13 0a 2b 11 00 09 11 0a 08 11 0a 94 d2 9c 00 11 0a 17 58 13 0a 11 0a 08 8e 69 fe 04 13 0b 11 0b 2d e2 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}