rule Trojan_BAT_PureLogsStealer_SO_MTB_2{
	meta:
		description = "Trojan:BAT/PureLogsStealer.SO!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 18 1f 39 61 13 18 11 18 1f 35 59 45 05 00 00 00 0b 00 00 00 1a 00 00 00 23 00 00 00 2a 00 00 00 3d 00 00 00 1f 2e 28 ec 00 00 06 13 18 2b d0 08 07 6f 0f 00 00 0a 5d 13 05 17 13 18 2b c1 11 06 2c 22 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}