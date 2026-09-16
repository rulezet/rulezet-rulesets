rule Trojan_AndroidOS_SmsThief_PS{
	meta:
		description = "Trojan:AndroidOS/SmsThief.PS,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6e 73 74 5f 6f 66 66 5f 64 65 74 61 69 6c 73 } 		$a_01_1 = {63 6f 6e 73 74 5f 67 63 6d 5f 73 65 6e 64 5f 73 6d 73 } 		$a_01_2 = {63 6f 6e 73 74 5f 6f 6e 5f 73 61 76 65 5f 73 6d 73 } 		$a_01_3 = {63 6f 6e 73 74 5f 65 72 72 6f 72 5f 72 65 67 69 73 74 65 72 5f 62 6f 74 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=6
 
}