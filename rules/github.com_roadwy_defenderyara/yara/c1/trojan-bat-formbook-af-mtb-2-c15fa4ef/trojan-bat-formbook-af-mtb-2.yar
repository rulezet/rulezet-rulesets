rule Trojan_BAT_FormBook_AF_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 16 73 ?? ?? ?? 0a 0d 09 07 6f ?? ?? ?? 0a 07 13 05 de 15 09 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}