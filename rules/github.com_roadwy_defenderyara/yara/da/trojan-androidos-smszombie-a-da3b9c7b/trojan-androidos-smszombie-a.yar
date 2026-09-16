rule Trojan_AndroidOS_SmsZombie_A{
	meta:
		description = "Trojan:AndroidOS/SmsZombie.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 61 73 20 64 6f 20 43 6c 65 61 72 20 6c 6f 67 63 61 74 20 63 61 63 68 65 } 		$a_01_1 = {2f 70 68 6f 6e 65 2e 78 6d 6c } 		$a_01_2 = {53 54 41 52 54 31 31 31 } 		$a_01_3 = {41 6e 64 70 68 6f 6e 65 41 63 74 69 76 69 74 79 2e 6a 61 76 61 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}