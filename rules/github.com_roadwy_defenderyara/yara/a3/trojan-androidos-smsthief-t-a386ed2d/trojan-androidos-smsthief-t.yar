rule Trojan_AndroidOS_SmsThief_T{
	meta:
		description = "Trojan:AndroidOS/SmsThief.T,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {76 70 6e 77 61 72 6e 69 6e 67 32 } 		$a_01_1 = {73 68 6f 72 74 61 6c 6c 5f 42 52 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}