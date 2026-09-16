rule Trojan_BAT_Rozena_NR_MTB_5{
	meta:
		description = "Trojan:BAT/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 04 8e 69 13 05 7e ?? 00 00 0a 20 00 10 00 00 20 00 30 00 00 1f 40 28 ?? 00 00 06 13 06 11 04 16 11 06 11 05 } 		$a_03_1 = {7e 13 00 00 0a 16 11 06 7e ?? 00 00 0a 16 7e ?? 00 00 0a 28 ?? 00 00 06 13 07 11 07 15 28 ?? 00 00 06 26 } 		$a_01_2 = {73 68 61 6e 65 6b 68 61 6e 74 61 75 6e 39 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_01_2  & 1)*1) >=7
 
}