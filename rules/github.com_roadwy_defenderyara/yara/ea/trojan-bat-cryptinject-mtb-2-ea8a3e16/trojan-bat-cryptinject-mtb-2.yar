rule Trojan_BAT_CryptInject_MTB_2{
	meta:
		description = "Trojan:BAT/CryptInject!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {08 0d 09 13 04 11 04 13 05 11 05 20 ?? ?? ?? ?? 28 ?? 00 00 06 28 ?? 00 00 06 13 06 11 06 28 ?? 00 00 0a 13 07 11 07 6f ?? 00 00 0a 13 08 11 08 14 14 6f ?? 00 00 0a 26 17 28 ?? 00 00 0a 2b 09 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}