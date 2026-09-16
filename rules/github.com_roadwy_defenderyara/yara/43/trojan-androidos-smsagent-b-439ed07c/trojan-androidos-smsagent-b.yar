rule Trojan_AndroidOS_SmsAgent_B{
	meta:
		description = "Trojan:AndroidOS/SmsAgent.B,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 6f 64 65 46 72 6f 6d 50 61 6e 65 6c } 		$a_01_1 = {2f 38 39 2e 32 33 2e 39 38 2e 31 36 2f 73 65 6e 64 5f 64 61 74 61 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}