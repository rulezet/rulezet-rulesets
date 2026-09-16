rule Trojan_BAT_FormBook_BG_MTB{
	meta:
		description = "Trojan:BAT/FormBook.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 2d 02 06 07 28 ?? 00 00 06 0c 04 03 6f ?? 00 00 0a 59 0d 03 08 09 28 ?? 00 00 06 03 08 09 28 ?? 00 00 06 03 04 28 ?? 00 00 06 07 17 58 0b 07 02 6f ?? 00 00 0a 32 } 		$a_03_1 = {02 03 16 61 04 16 60 6f ?? 00 00 0a 0a [0-04] 28 ?? 00 00 0a 16 61 28 ?? 00 00 0a 2a } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}