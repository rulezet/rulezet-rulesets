rule Trojan_BAT_FormBook_ABO_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 0a 16 0b 2b 0f 00 06 07 58 02 03 07 58 91 52 00 07 17 58 0b 07 05 fe 04 0c 08 2d e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}