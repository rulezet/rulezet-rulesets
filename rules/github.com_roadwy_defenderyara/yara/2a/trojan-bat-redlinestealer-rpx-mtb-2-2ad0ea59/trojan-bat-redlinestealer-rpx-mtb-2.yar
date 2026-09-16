rule Trojan_BAT_RedlineStealer_RPX_MTB_2{
	meta:
		description = "Trojan:BAT/RedlineStealer.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {26 20 06 00 00 00 38 f2 fb ff ff 16 13 04 20 05 00 00 00 fe 0e 03 00 38 dd fb ff ff 1f 0a 13 00 20 06 00 00 00 38 d3 fb ff ff 11 00 11 0a 3e 56 ff ff ff 20 0a 00 00 00 38 c0 fb ff ff 11 04 17 58 13 04 20 1e 00 00 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}