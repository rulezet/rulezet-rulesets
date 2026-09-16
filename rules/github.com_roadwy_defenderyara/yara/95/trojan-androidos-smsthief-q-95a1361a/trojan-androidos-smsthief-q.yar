rule Trojan_AndroidOS_SmsThief_Q{
	meta:
		description = "Trojan:AndroidOS/SmsThief.Q,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 63 63 6f 75 6e 74 20 41 6e 64 20 4d 6f 62 69 6c 65 20 4e 75 6d 62 65 72 20 56 65 72 69 66 79 20 53 75 63 65 73 73 66 75 6c 6c 79 2e 2e } 		$a_01_1 = {53 4d 53 20 62 6f 64 79 20 66 6f 72 77 61 72 64 65 64 20 74 6f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}