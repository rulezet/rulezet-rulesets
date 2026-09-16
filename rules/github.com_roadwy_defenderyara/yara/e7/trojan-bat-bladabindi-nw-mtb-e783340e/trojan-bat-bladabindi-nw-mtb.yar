rule Trojan_BAT_Bladabindi_NW_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 74 ?? 00 00 1b 16 1f 3a 9d 11 04 75 ?? 00 00 1b 20 } 		$a_03_1 = {13 04 11 04 74 ?? 00 00 1b 16 1f 3a 9d 11 04 75 ?? 00 00 1b 6f ?? 00 00 0a 17 9a } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}