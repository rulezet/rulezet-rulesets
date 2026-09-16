rule Trojan_BAT_Heracles_NHE_MTB_3{
	meta:
		description = "Trojan:BAT/Heracles.NHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b fa 02 06 74 ?? 00 00 1b 18 9a 06 74 ?? 00 00 1b 1a 9a 28 ?? 00 00 06 } 		$a_01_1 = {51 65 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } 		$a_01_2 = {53 70 65 63 69 61 6c 44 69 72 65 63 74 6f 72 69 65 73 50 72 6f 78 79 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}