rule Trojan_BAT_RedLine_RPY_MTB_3{
	meta:
		description = "Trojan:BAT/RedLine.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 11 08 08 11 08 91 11 04 11 08 09 5d 91 61 d2 9c 1f 09 13 0f 38 6b ff ff ff 06 6f d2 00 00 0a 0b 19 13 0f 38 5c ff ff ff 11 08 2c 19 1b 13 0f 38 50 ff ff ff 16 13 08 1d 13 0f 38 45 ff ff ff 11 08 17 58 13 08 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}