rule Trojan_BAT_Remcos_AR_MTB_15{
	meta:
		description = "Trojan:BAT/Remcos.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 04 06 11 04 8e 69 5d 91 09 06 91 61 d2 6f ?? ?? ?? 0a 06 0c 08 17 58 0a 06 09 8e 69 32 dc 11 05 6f ?? ?? ?? 0a 13 06 16 2d ee } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}