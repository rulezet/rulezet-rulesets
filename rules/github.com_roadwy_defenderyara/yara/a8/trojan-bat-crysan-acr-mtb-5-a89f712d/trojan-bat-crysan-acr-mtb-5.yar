rule Trojan_BAT_Crysan_ACR_MTB_5{
	meta:
		description = "Trojan:BAT/Crysan.ACR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 06 2b 73 11 06 6f ?? 00 00 0a 74 ?? 00 00 01 13 07 00 1b 28 ?? 00 00 0a 00 07 11 07 6f ?? 00 00 0a 6f ?? 00 00 0a 13 08 11 08 2c 49 00 1f 0e 28 ?? 00 00 0a 00 72 ?? 04 00 70 11 04 6f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}