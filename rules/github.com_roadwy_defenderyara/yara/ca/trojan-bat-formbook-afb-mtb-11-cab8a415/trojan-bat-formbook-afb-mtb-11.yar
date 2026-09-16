rule Trojan_BAT_FormBook_AFB_MTB_11{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 18 6f ?? ?? ?? 0a 00 06 18 6f ?? ?? ?? 0a 00 06 02 7b 04 00 00 04 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 0b 07 03 16 03 8e 69 6f ?? ?? ?? 0a 0c 08 0d de 0b } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}