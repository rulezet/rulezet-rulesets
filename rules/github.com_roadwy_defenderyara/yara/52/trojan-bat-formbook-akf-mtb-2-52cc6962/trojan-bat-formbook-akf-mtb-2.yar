rule Trojan_BAT_Formbook_AKF_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.AKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {6c 07 16 9a 16 99 5a a1 25 17 12 09 28 ?? 00 00 0a 6c 07 17 9a 17 99 5a a1 25 18 12 09 28 ?? 00 00 0a 6c 07 18 9a 18 99 5a a1 13 0a 19 8d ?? 00 00 01 25 16 11 0a 16 99 d2 9c 25 17 11 0a 17 99 } 		$a_01_1 = {48 61 72 76 65 73 74 50 69 67 6d 65 6e 74 53 65 71 75 65 6e 63 65 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}