rule Trojan_BAT_Heracles_AHC_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 00 09 08 16 73 ?? ?? ?? 0a 13 04 00 73 ?? ?? ?? 0a 13 05 00 11 04 11 05 6f ?? ?? ?? 0a 00 11 05 6f ?? ?? ?? 0a 0a 00 de 14 11 05 14 fe 01 13 07 11 07 2d 08 11 05 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}