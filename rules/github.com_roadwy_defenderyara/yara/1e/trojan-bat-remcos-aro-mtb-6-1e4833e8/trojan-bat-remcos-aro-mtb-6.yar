rule Trojan_BAT_Remcos_ARO_MTB_6{
	meta:
		description = "Trojan:BAT/Remcos.ARO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0b 16 0c 2b 15 00 06 08 06 08 91 07 08 07 8e 69 5d 93 61 d2 9c 00 08 17 58 0c 08 06 8e 69 fe 04 } 		$a_03_1 = {a2 25 1a 11 18 a2 25 1b 72 ?? ?? ?? 70 a2 25 1c 11 0e a2 25 1d 11 08 a2 25 1e 11 0d a2 25 1f 09 11 13 a2 28 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}