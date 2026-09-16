rule Trojan_BAT_Heracles_AHE_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 19 15 28 ?? 00 00 0a 00 17 28 ?? 00 00 0a b7 28 ?? 00 00 0a 0a 17 12 00 15 6a 16 28 ?? 00 00 0a 00 17 8d 4d 00 00 01 0d 09 16 17 9e 09 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}