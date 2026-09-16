rule Trojan_BAT_FormBook_AFK_MTB_22{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 06 2b 2e 11 05 11 06 9a 13 07 00 11 04 6f ?? 01 00 0a 11 07 28 ?? 00 00 0a 13 08 11 08 2c 0b 00 06 07 11 04 a2 07 17 58 } 		$a_03_1 = {0d 2b 48 00 06 09 06 8e 69 5d 06 09 06 8e 69 5d 91 07 09 07 6f ?? 01 00 0a 5d 6f ?? 02 00 0a 61 28 ?? 00 00 0a 06 09 17 58 06 8e 69 5d 91 28 ?? 02 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? 02 00 0a 9c 00 09 15 58 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}