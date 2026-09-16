rule Trojan_BAT_AveMaria_NMA_MTB_2{
	meta:
		description = "Trojan:BAT/AveMaria.NMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 11 06 20 ?? ?? ?? cd 5a 20 ?? ?? ?? 34 61 38 ?? ?? ?? ff 02 7b ?? ?? ?? 04 20 ?? ?? ?? 18 28 ?? ?? ?? 2b 28 ?? ?? ?? 06 } 		$a_01_1 = {43 43 30 31 2e 66 72 6d 44 61 6e 68 53 61 63 68 53 61 6e 50 68 61 6d 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}