rule Trojan_AndroidOS_Smsthief_P_2{
	meta:
		description = "Trojan:AndroidOS/Smsthief.P,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 61 70 70 43 6f 6d 6d 6f 6e 2e 6f 72 67 } 		$a_01_1 = {49 2c 68 61 76 65 20 46 75 63 6b 69 6e 67 20 59 6f 75 72 20 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}