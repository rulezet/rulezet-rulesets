rule Trojan_BAT_FormBook_AFO_MTB_17{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 13 04 16 13 05 2b 19 11 04 11 05 a3 ?? 00 00 01 13 06 09 11 06 6f ?? 00 00 0a 11 05 17 58 13 05 11 05 11 04 8e 69 32 df } 		$a_03_1 = {0a 16 0b 38 ?? 00 00 00 06 07 17 5b 7e ?? 00 00 0a a4 ?? 00 00 01 07 17 58 0b 07 02 8e 69 32 e8 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}