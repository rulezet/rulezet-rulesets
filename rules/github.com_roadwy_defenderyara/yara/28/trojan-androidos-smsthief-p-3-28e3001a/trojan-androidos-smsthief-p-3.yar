rule Trojan_AndroidOS_Smsthief_P_3{
	meta:
		description = "Trojan:AndroidOS/Smsthief.P,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 6d 73 46 6f 72 77 61 72 64 69 6e 67 53 65 72 76 69 63 65 } 		$a_01_1 = {45 72 72 6f 72 20 66 6f 72 77 61 72 64 69 6e 67 20 53 4d 53 20 62 6f 64 79 3a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}