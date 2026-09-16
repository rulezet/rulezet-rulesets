rule Trojan_BAT_AveMaria_NEA_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 0d 00 00 04 11 04 7e ?? ?? ?? 04 11 04 91 20 ?? ?? ?? 00 59 d2 9c 00 11 04 17 58 13 04 11 04 7e ?? ?? ?? 04 8e 69 fe 04 } 		$a_01_1 = {49 51 6e 75 69 6e } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}