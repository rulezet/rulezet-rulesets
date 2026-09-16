rule Trojan_BAT_PureLogsStealer_SO_MTB_3{
	meta:
		description = "Trojan:BAT/PureLogsStealer.SO!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 17 11 0a 1f 1f 5f 62 13 0b 11 07 11 0b 5f 11 0a 1f 1f 5f 63 13 0c 11 08 11 0b 5f 11 0a 1f 1f 5f 63 13 0d 11 0c 11 0d fe 01 16 fe 01 13 0e 11 0e 39 0e 00 00 00 00 11 09 11 0b 60 13 09 00 38 0a 00 00 00 00 16 13 0f 38 00 00 00 00 00 00 11 0a 17 58 13 0a 11 0a 1e fe 04 13 10 11 10 2d a0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}