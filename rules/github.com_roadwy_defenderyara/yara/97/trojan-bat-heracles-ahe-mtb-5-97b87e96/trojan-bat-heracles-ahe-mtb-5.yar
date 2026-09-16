rule Trojan_BAT_Heracles_AHE_MTB_5{
	meta:
		description = "Trojan:BAT/Heracles.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0b 07 8e 69 8d 10 00 00 01 0c 16 0d 38 29 00 00 00 07 09 91 06 59 20 00 01 00 00 5d 13 04 11 04 16 3c 0a 00 00 00 11 04 20 00 01 00 00 58 13 04 08 09 11 04 d2 9c 09 17 58 0d 09 07 8e 69 32 d1 } 		$a_03_1 = {0b 06 8e 69 07 8e 69 59 8d ?? 00 00 01 0c 06 07 07 8e 69 28 ?? 00 00 0a 06 07 8e 69 08 16 08 8e 69 28 ?? 00 00 0a 28 ?? 00 00 0a 0d 09 20 80 00 00 00 6f } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}