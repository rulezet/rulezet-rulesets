rule Trojan_BAT_PureLogsStealer_APL_MTB{
	meta:
		description = "Trojan:BAT/PureLogsStealer.APL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 07 11 06 11 07 16 1a 6f ?? 00 00 0a 26 11 07 16 28 ?? 00 00 0a 13 08 11 06 16 73 ?? 00 00 0a 13 09 11 09 08 6f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}