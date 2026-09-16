rule Trojan_BAT_FormBook_AFK_MTB_17{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 07 13 04 16 13 05 2b 3c 11 04 11 05 9a 0c 08 6f ?? 00 00 0a 04 28 ?? 00 00 0a 2c 22 72 ?? 00 00 70 08 72 ?? 00 00 70 18 8d ?? 00 00 01 13 06 11 06 16 03 a2 11 06 28 ?? 00 00 06 0d de 10 11 05 17 58 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}