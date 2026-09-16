rule Trojan_AndroidOS_SmsThief_K_2{
	meta:
		description = "Trojan:AndroidOS/SmsThief.K,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 64 68 72 75 76 2e 73 6d 73 72 65 63 65 76 69 65 72 } 		$a_01_1 = {2f 6f 6e 6c 69 6e 65 6b 6b 70 61 79 2e 77 69 78 73 69 74 65 2e 63 6f 6d } 		$a_01_2 = {64 6f 63 74 6f 72 65 61 70 70 6f 69 6e 6d 65 6e 74 2e 77 69 78 73 69 74 65 2e 63 6f 6d } 		$a_01_3 = {63 75 73 74 6f 6d 65 72 61 67 69 73 74 72 61 69 6f 6e 2e 77 69 78 73 69 74 65 2e 63 6f 6d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}