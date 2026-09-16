rule Trojan_BAT_AveMaria_RPY_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 11 06 09 11 06 91 20 37 07 00 00 59 d2 9c 11 06 17 58 13 06 11 06 09 8e 69 32 e4 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}