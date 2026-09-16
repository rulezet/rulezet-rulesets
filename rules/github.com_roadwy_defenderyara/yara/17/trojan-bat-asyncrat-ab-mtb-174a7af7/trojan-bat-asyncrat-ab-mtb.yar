rule Trojan_BAT_AsyncRAT_AB_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 07 08 6f ?? 00 00 0a 13 07 03 06 6f ?? 00 00 0a 59 13 08 11 08 16 3e ?? 00 00 00 06 12 07 28 ?? 00 00 0a 6f ?? 00 00 0a 11 08 17 59 13 08 11 08 16 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}