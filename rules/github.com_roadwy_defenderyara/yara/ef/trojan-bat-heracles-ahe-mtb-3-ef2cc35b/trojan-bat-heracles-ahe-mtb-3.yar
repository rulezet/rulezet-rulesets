rule Trojan_BAT_Heracles_AHE_MTB_3{
	meta:
		description = "Trojan:BAT/Heracles.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 18 02 03 07 28 ?? ?? ?? 06 0a 06 2d 08 07 80 ?? 04 00 04 14 2a 07 17 58 0b 07 7e ?? 04 00 04 8e 69 32 de 02 14 51 } 		$a_01_1 = {4e 00 69 00 63 00 65 00 48 00 61 00 73 00 68 00 51 00 75 00 69 00 63 00 6b 00 4d 00 69 00 6e 00 65 00 72 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}