rule Trojan_AndroidOS_Gigabud_D{
	meta:
		description = "Trojan:AndroidOS/Gigabud.D,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 76 69 72 62 6f 78 2f 53 74 75 62 41 70 70 } 		$a_01_1 = {6c 30 64 66 32 61 61 65 34 24 6a 6e 74 6d } 		$a_01_2 = {49 36 37 36 65 66 62 35 62 5f 30 33 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}