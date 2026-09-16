rule Trojan_BAT_RedlineStealer_RPY_MTB{
	meta:
		description = "Trojan:BAT/RedlineStealer.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {71 1f 00 00 01 20 9a 00 00 00 61 d2 81 1f 00 00 01 02 50 06 8f 1f 00 00 01 25 71 1f 00 00 01 1f 40 58 d2 81 1f 00 00 01 02 50 06 8f 1f 00 00 01 25 71 1f 00 00 01 1f 43 59 d2 81 1f 00 00 01 02 50 06 8f 1f 00 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}