rule Trojan_BAT_nJRat_ANJ_MTB_7{
	meta:
		description = "Trojan:BAT/nJRat.ANJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {14 0a 17 0b 2b 3b 00 02 07 28 ?? 00 00 0a 28 ?? 00 00 0a 03 07 03 6f ?? 00 00 0a 5d 17 58 28 ?? 00 00 0a 28 ?? 00 00 0a 59 0c 06 08 28 ?? 00 00 0a 8c ?? 00 00 01 28 ?? 00 00 0a 0a 00 07 17 } 		$a_03_1 = {58 17 59 17 58 17 59 17 58 8d ?? 00 00 01 0c 08 8e 69 17 59 0d 16 13 04 2b 1b 08 11 04 07 11 04 1e 5a 1e 6f ?? 00 00 0a 18 28 ?? 00 00 0a 9c 11 04 17 58 13 04 11 04 09 fe 02 16 fe 01 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}