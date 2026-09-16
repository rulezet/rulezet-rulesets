rule Trojan_AndroidOS_SmsThief_Z_2{
	meta:
		description = "Trojan:AndroidOS/SmsThief.Z,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 67 69 6e 41 63 74 69 76 69 74 79 20 2d 20 43 6f 6e 66 69 67 75 72 69 6e 67 20 73 63 72 65 65 6e 20 6f 6e 2f 6f 66 66 2e 2e } 		$a_01_1 = {53 61 76 65 64 20 72 65 6d 6f 74 65 20 73 65 73 73 69 6f 6e 20 69 6e 66 6f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}