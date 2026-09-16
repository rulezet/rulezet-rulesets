rule Trojan_BAT_DarkComet_ADK_MTB_8{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 06 02 06 91 03 06 72 ?? 00 00 70 6f ?? 00 00 0a 5d 91 06 1b 58 03 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 9c 06 17 58 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}