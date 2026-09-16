rule Trojan_BAT_Mamut_NM_MTB_2{
	meta:
		description = "Trojan:BAT/Mamut.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 72 69 76 61 74 65 20 53 70 6f 6f 66 65 72 20 62 79 20 4c 65 76 } 		$a_01_1 = {41 73 53 74 72 6f 6e 67 41 73 46 75 63 6b 20 6f 62 66 75 73 63 61 74 6f 72 20 62 79 20 43 68 61 72 74 65 72 } 		$a_01_2 = {4c 65 76 73 53 70 6f 6f 66 65 72 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}