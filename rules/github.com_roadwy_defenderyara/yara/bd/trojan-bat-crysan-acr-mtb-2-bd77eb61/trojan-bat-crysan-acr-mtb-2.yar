rule Trojan_BAT_Crysan_ACR_MTB_2{
	meta:
		description = "Trojan:BAT/Crysan.ACR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 2d 16 00 06 16 6f ?? 00 00 0a 0c 16 0d 2b 1a 16 2d b5 08 09 91 13 04 00 07 11 04 6f ?? 00 00 0a 00 00 09 19 2c 04 17 58 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}