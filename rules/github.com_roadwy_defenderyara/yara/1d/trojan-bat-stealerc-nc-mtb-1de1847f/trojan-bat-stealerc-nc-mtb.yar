rule Trojan_BAT_Stealerc_NC_MTB{
	meta:
		description = "Trojan:BAT/Stealerc.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 00 1c 13 01 12 01 1d 13 03 12 03 6f ?? 00 00 06 26 } 		$a_03_1 = {02 8e 69 1f 11 da 17 d6 8d ?? 00 00 01 13 0b 20 ?? 00 00 00 28 ?? 00 00 06 3a } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}