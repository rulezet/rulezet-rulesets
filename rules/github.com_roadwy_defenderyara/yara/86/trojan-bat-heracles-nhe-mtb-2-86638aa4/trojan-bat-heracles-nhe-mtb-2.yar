rule Trojan_BAT_Heracles_NHE_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.NHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {38 00 00 00 00 00 11 04 11 0c 28 ?? 00 00 06 20 ?? 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 3a ?? 00 00 00 26 20 ?? 00 00 00 38 ?? 00 00 00 fe ?? ?? 00 } 		$a_01_1 = {4f 69 78 6c 79 78 6c 62 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}