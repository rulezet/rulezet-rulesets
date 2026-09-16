rule Trojan_AndroidOS_Smsthief_P_4{
	meta:
		description = "Trojan:AndroidOS/Smsthief.P,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {69 73 50 68 6f 6e 65 4d 6f 76 65 20 74 65 6c 3a 2a 2a 32 31 2a 31 32 31 25 32 33 } 		$a_01_1 = {73 6d 73 20 63 6c 69 65 6e 74 20 68 61 64 20 63 68 61 6e 67 65 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}