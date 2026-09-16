rule Trojan_BAT_Formbook_AKF_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 13 04 2b 16 07 11 04 06 11 04 19 5a 58 1f 18 5d 1f 0c 59 9e 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 05 11 05 2d dd } 		$a_01_1 = {0a 16 13 07 2b 1c 00 06 11 07 11 07 1f 11 5a 11 07 18 62 61 20 aa 00 00 00 60 9e 00 11 07 17 58 13 07 11 07 06 8e 69 fe 04 13 08 11 08 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}