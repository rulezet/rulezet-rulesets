rule Trojan_AndroidOS_FakeInstSms_B{
	meta:
		description = "Trojan:AndroidOS/FakeInstSms.B,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 68 61 6e 6b 20 74 45 58 74 20 6e 6f 74 20 66 6f 75 6e 64 20 69 6e 20 70 6e 67 } 		$a_01_1 = {74 65 72 6d 61 74 65 2f 52 75 6c 65 41 63 74 69 76 69 74 79 } 		$a_01_2 = {72 65 67 5f 68 6f 73 74 } 		$a_01_3 = {45 72 72 6f 72 20 73 65 6e 64 69 6e 67 20 73 6d 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}