rule Trojan_BAT_Heracles_AHC_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 2d 18 08 09 18 5b 06 09 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 09 18 58 0d 09 07 32 e1 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}