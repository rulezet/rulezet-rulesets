rule Trojan_BAT_Heracles_ARR_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 17 9c 1f 11 28 ?? ?? ?? ?? 2c 15 1f 43 28 ?? ?? ?? ?? 2d 09 1f 58 } 		$a_03_1 = {0a 2c 08 7e ?? ?? ?? ?? 0d de 42 07 28 ?? ?? ?? 06 0c 08 7e } 	condition:
		((#a_03_0  & 1)*11+(#a_03_1  & 1)*9) >=20
 
}