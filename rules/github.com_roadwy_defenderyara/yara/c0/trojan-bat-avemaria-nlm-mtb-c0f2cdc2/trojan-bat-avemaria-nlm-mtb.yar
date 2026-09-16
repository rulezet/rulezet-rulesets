rule Trojan_BAT_AveMaria_NLM_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NLM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 6a 00 00 0a 13 05 1a 8d ?? ?? ?? 01 25 16 72 ?? ?? ?? 70 a2 25 17 72 ?? ?? ?? 70 a2 25 18 72 ?? ?? ?? 70 a2 25 19 72 ?? ?? ?? 70 a2 13 06 72 ?? ?? ?? 70 28 ?? ?? ?? 0a } 		$a_01_1 = {51 75 61 6e 74 75 6d 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}