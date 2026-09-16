rule Trojan_BAT_Heracles_AHL_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {74 4e 00 00 01 28 ?? ?? ?? 06 74 01 00 00 1b 28 ?? ?? ?? 06 17 2d 03 26 de 06 0a 2b fb 26 de d0 06 2a } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}