rule Trojan_BAT_Bladabindi_NB_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {20 29 27 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 02 18 16 8d 01 00 00 01 28 ?? 00 00 0a 0a 06 2a } 		$a_03_1 = {20 66 08 00 00 28 ?? 00 00 0a 20 45 15 00 00 72 bb 02 00 70 28 ?? 00 00 06 28 ?? 00 00 0a 0a 06 2a } 		$a_01_2 = {63 78 7a 63 78 7a 78 63 7a } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}