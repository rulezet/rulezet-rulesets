rule Trojan_BAT_Crysan_ACR_MTB_3{
	meta:
		description = "Trojan:BAT/Crysan.ACR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 08 06 73 12 00 00 0a 07 6f ?? 00 00 0a 00 73 14 00 00 0a 0d 09 20 e8 03 00 00 20 b8 0b 00 00 6f ?? 00 00 0a 13 04 11 04 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}