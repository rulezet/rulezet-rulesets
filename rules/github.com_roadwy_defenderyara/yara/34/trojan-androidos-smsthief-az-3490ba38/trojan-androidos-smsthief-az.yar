rule Trojan_AndroidOS_SmsThief_AZ{
	meta:
		description = "Trojan:AndroidOS/SmsThief.AZ,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {7a 65 62 72 36 2f 54 68 69 73 41 70 70 6c 69 63 61 74 69 6f 6e } 		$a_01_1 = {55 70 6c 6f 61 64 53 6d 73 2e 70 68 70 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}