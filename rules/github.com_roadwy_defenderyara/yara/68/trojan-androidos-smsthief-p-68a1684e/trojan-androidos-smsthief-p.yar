rule Trojan_AndroidOS_Smsthief_P{
	meta:
		description = "Trojan:AndroidOS/Smsthief.P,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 4d 53 52 65 63 65 69 76 65 72 43 6c 61 73 73 } 		$a_01_1 = {53 4e 53 44 42 42 53 4a 4e 2f 49 53 53 41 53 44 53 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}