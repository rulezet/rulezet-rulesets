rule Trojan_BAT_nJRat_ANJ_MTB_6{
	meta:
		description = "Trojan:BAT/nJRat.ANJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 0b 16 0c 2b 52 07 08 6f ?? 00 00 0a 0d 16 13 04 2b 33 7e 5a 00 00 04 11 04 6f ?? 00 00 0a 09 33 1e 06 7e 59 00 00 04 11 04 6f ?? 00 00 0a 13 05 12 05 28 ?? 01 00 0a 28 } 		$a_03_1 = {2b 12 02 28 ?? 00 00 06 2c 06 16 28 ?? 00 00 0a 06 17 58 0a 06 73 15 00 00 0a 19 1f 0a 6f } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}