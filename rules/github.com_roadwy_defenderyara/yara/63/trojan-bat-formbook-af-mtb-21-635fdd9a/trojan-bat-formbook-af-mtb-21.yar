rule Trojan_BAT_FormBook_AF_MTB_21{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 11 0a 11 09 6f ?? ?? ?? 0a 13 0b 16 13 0c 11 05 11 08 9a 72 46 04 00 70 28 ?? ?? ?? 0a 13 0d 11 0d 2c 0d 00 12 0b 28 ?? ?? ?? 0a 13 0c 00 2b 42 11 05 11 08 9a 72 4a 04 00 70 28 ?? ?? ?? 0a 13 0e 11 0e 2c 0d 00 12 0b 28 ?? ?? ?? 0a 13 0c 00 2b 20 11 05 11 08 9a 72 4e 04 00 70 28 ?? ?? ?? 0a 13 0f 11 0f 2c 0b 00 12 0b 28 ?? ?? ?? 0a 13 0c 00 07 11 0c } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}