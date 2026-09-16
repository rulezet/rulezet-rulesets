rule Trojan_BAT_RedlineStealer_RPJ_MTB{
	meta:
		description = "Trojan:BAT/RedlineStealer.RPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 2d 00 00 0a 0a 12 00 23 00 00 00 00 00 00 24 40 28 2e 00 00 0a 0b 2b 23 08 2d 20 20 00 00 00 00 7e 41 00 00 04 7b 2c 00 00 04 2d 2f 45 02 00 00 00 23 00 00 00 df ff ff ff 2b 21 07 28 2d 00 00 0a 28 2f 00 00 0a 0c } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}