rule Trojan_BAT_Nanocore_ANO_MTB_2{
	meta:
		description = "Trojan:BAT/Nanocore.ANO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 16 0b 2b 49 16 0c 2b 2c 09 07 08 6f ?? 00 00 0a 26 09 07 08 6f ?? 00 00 0a 13 08 11 08 28 ?? 00 00 0a 13 09 11 05 11 04 11 09 28 ?? 00 00 0a 9c 08 17 58 0c 08 09 6f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}