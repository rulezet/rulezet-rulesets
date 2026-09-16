rule Trojan_AndroidOS_FakeInstSms_C{
	meta:
		description = "Trojan:AndroidOS/FakeInstSms.C,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 75 74 6f 72 75 6e 42 72 6f 61 64 63 61 73 74 52 65 63 65 69 76 65 72 } 		$a_01_1 = {2f 63 6f 6e 6e 65 63 74 2e 70 68 70 00 } 		$a_01_2 = {73 74 61 74 20 6d 61 6e 6e 75 61 6c 79 00 } 		$a_01_3 = {53 6d 73 52 65 63 69 76 65 72 2e 6a 61 76 61 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}