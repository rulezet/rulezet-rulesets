rule Trojan_BAT_AveMaria_NAA_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 20 1f d8 36 76 5a 20 ?? ?? ?? 98 61 38 ?? ?? ?? ff 00 07 20 ?? ?? ?? 5f 5a 20 ?? ?? ?? 69 61 38 ?? ?? ?? ff 02 7b ?? ?? ?? 04 1a 28 ?? ?? ?? 06 } 		$a_01_1 = {41 69 72 70 6f 72 74 42 61 67 67 61 67 65 2e 50 72 6f 70 65 72 74 69 65 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}