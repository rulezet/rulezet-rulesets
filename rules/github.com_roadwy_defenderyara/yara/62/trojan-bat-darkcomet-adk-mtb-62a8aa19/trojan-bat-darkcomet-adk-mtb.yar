rule Trojan_BAT_DarkComet_ADK_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 1b 03 06 7e ?? ?? ?? 04 5d 91 0b 02 06 02 06 91 07 61 28 ?? ?? ?? 0a 9c 06 17 58 0a 06 02 8e 69 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}