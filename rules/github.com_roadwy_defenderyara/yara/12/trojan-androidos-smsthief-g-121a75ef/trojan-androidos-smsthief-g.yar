rule Trojan_AndroidOS_Smsthief_G{
	meta:
		description = "Trojan:AndroidOS/Smsthief.G,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 79 64 69 61 74 65 61 6d 2e 62 61 6c } 		$a_01_1 = {5f 6c 79 64 69 61 5f 73 65 6e 64 73 6d 73 } 		$a_01_2 = {67 65 74 65 77 61 79 70 6f 72 74 2e 74 78 74 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}