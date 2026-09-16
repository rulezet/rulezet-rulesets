rule Trojan_BAT_Ursu_AU_MTB{
	meta:
		description = "Trojan:BAT/Ursu.AU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 06 2d 15 7e 12 00 00 0a 02 6f ?? ?? ?? 0a 03 04 1a 6f ?? ?? ?? 0a de 24 06 03 6f ?? ?? ?? 0a 04 2e 09 06 03 04 1a 6f ?? ?? ?? 0a de 0a 06 2c 06 06 6f ?? ?? ?? 0a dc de 03 26 de 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}