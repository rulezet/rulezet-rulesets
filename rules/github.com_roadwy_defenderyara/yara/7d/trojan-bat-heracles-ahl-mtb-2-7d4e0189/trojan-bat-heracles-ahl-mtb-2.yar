rule Trojan_BAT_Heracles_AHL_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.AHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 8b 00 00 70 28 ?? ?? ?? 06 1b 2d 1c 26 28 ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 } 		$a_01_1 = {02 06 02 07 91 9c 02 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e9 06 07 32 de } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}