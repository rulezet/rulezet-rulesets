rule Trojan_BAT_FormBook_AF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 25 26 6f ?? ?? ?? 0a 00 de 02 2b 2d 08 20 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}