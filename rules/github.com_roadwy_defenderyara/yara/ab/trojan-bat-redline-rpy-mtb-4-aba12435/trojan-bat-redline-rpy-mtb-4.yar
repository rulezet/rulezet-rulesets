rule Trojan_BAT_RedLine_RPY_MTB_4{
	meta:
		description = "Trojan:BAT/RedLine.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 02 06 02 06 91 66 d2 9c 02 06 8f 18 00 00 01 25 71 18 00 00 01 20 83 00 00 00 59 d2 81 18 00 00 01 02 06 8f 18 00 00 01 25 71 18 00 00 01 1f 25 58 d2 81 18 00 00 01 00 06 17 58 0a 06 02 8e 69 fe 04 0b 07 2d b9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}