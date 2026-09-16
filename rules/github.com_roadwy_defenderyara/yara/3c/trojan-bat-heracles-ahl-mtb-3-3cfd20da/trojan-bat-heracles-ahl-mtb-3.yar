rule Trojan_BAT_Heracles_AHL_MTB_3{
	meta:
		description = "Trojan:BAT/Heracles.AHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 09 2b 33 11 08 11 09 9a 13 0a 11 0a 73 ?? 01 00 0a 13 0b 00 11 0b 6f ?? 01 00 0a 00 de 10 25 28 ?? 00 00 0a 13 0c 00 28 ?? 00 00 0a de 00 00 00 11 09 17 d6 13 09 11 09 11 08 8e 69 } 		$a_01_1 = {43 00 68 00 65 00 63 00 6b 00 58 00 53 00 45 00 4f 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}