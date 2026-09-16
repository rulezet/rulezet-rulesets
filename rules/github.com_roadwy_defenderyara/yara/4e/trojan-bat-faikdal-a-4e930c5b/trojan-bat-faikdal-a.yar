rule Trojan_BAT_Faikdal_A{
	meta:
		description = "Trojan:BAT/Faikdal.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {2e 00 63 00 6f 00 6d 00 [0-20] 68 00 [0-18] 74 00 [0-18] 74 00 [0-18] 70 00 [0-18] 3a 00 [0-18] 2f 00 [0-18] 2f 00 } 		$a_01_1 = {64 6f 77 6e 6c 6f 61 64 63 66 69 6c 65 } 		$a_01_2 = {6b 69 6c 6c 6f 74 68 65 72 } 		$a_01_3 = {73 61 76 65 74 6f 6c 6f 67 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}