rule Trojan_BAT_FormBook_AFK_MTB_19{
	meta:
		description = "Trojan:BAT/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {58 11 15 11 15 8e 69 12 00 28 ?? 00 00 06 2d 02 16 2a 11 0d 1f 28 58 13 0d 11 11 17 58 68 13 11 11 11 04 07 1c 58 } 		$a_03_1 = {04 11 0d 1f 0c 58 28 ?? 00 00 0a 13 12 04 11 0d 1f 10 58 28 ?? 00 00 0a 13 13 04 11 0d 1f 14 58 28 ?? 00 00 0a 13 14 11 13 2c 33 11 13 8d ?? 00 00 01 13 15 04 11 14 11 15 16 11 13 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}