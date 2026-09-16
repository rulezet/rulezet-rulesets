rule Trojan_BAT_Barys_NL_MTB{
	meta:
		description = "Trojan:BAT/Barys.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {26 20 16 00 00 00 38 07 ?? ?? ?? 11 44 02 58 20 e2 ?? ?? ?? 11 00 59 11 01 61 61 11 0c 20 93 ?? ?? ?? 11 00 58 11 01 58 5f 61 13 41 } 		$a_03_1 = {11 1e 8e 69 13 27 20 0e 00 00 00 38 2a ?? ?? ?? 11 1e 11 09 11 25 11 23 61 19 11 1d 58 61 11 2b 61 d2 9c } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}