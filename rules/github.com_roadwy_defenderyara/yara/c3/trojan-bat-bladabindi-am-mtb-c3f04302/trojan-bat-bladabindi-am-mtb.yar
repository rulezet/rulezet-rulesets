rule Trojan_BAT_Bladabindi_AM_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {74 61 69 66 69 6c 65 6d 6f 69 31 } 		$a_01_1 = {55 70 64 61 74 61 2e 65 78 65 } 		$a_01_2 = {63 00 68 00 65 00 63 00 6b 00 2e 00 74 00 78 00 74 00 } 		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } 		$a_01_4 = {74 61 69 6d 75 74 69 } 		$a_01_5 = {67 65 74 5f 4b 68 61 6b 69 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}