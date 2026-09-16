rule Trojan_BAT_FormBook_AFK_MTB_15{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 3e 00 02 06 07 28 ?? 00 00 06 0c 04 03 6f ?? 01 00 0a 59 0d 03 08 09 28 ?? 00 00 06 00 03 08 09 28 ?? 00 00 06 00 03 6f ?? 01 00 0a 04 fe 04 16 fe 01 13 04 11 04 2c 02 2b 28 00 07 17 58 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}