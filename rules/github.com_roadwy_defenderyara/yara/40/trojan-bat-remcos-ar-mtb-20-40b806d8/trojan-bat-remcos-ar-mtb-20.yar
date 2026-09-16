rule Trojan_BAT_Remcos_AR_MTB_20{
	meta:
		description = "Trojan:BAT/Remcos.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 15 2b 28 00 11 13 11 15 18 6f ?? ?? ?? 0a 20 03 02 00 00 28 ?? ?? ?? 0a 13 17 11 14 11 17 6f ?? ?? ?? 0a 00 11 15 18 58 13 15 00 11 15 11 13 6f ?? ?? ?? 0a fe 04 13 18 11 18 2d c7 } 		$a_01_1 = {47 00 55 00 49 00 47 00 61 00 6d 00 65 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}