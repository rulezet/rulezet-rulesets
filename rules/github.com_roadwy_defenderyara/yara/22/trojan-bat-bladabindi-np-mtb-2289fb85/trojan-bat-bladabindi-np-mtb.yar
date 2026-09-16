rule Trojan_BAT_Bladabindi_NP_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {69 5f 53 68 69 74 74 65 64 5f 4d 79 5f 53 65 6c 66 2e 65 78 65 } 		$a_01_1 = {73 00 4b 00 69 00 44 00 74 00 4f 00 6f 00 4c 00 73 00 5f 00 57 00 68 00 59 00 5f 00 75 00 5f 00 4c 00 6f 00 4f 00 6b 00 49 00 67 00 5f 00 48 00 65 00 52 00 65 00 } 		$a_01_2 = {53 00 68 00 6f 00 70 00 43 00 68 00 6f 00 70 00 23 00 36 00 39 00 33 00 36 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}