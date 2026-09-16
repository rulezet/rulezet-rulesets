rule Trojan_BAT_FormBook_AFK_MTB_12{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 06 72 61 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 ?? 30 00 00 0a 28 ?? 00 00 06 0b 07 16 07 8e 69 6f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}