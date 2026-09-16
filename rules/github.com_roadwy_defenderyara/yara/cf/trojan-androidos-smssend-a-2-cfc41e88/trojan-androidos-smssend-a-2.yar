rule Trojan_AndroidOS_SmsSend_A_2{
	meta:
		description = "Trojan:AndroidOS/SmsSend.A,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 57 45 42 2d 49 4e 46 2f 70 61 67 65 73 2f 70 6c 61 79 2f 77 61 70 33 2f 62 69 6c 6c 2e 6a 73 70 70 } 		$a_01_1 = {77 61 70 42 69 6c 6c 55 72 6c } 		$a_01_2 = {2f 77 61 70 2f 6e 31 30 33 34 35 33 33 32 64 32 63 35 30 32 31 31 31 31 32 35 2e 6a 73 70 } 		$a_01_3 = {77 61 70 41 66 74 65 72 4d 69 67 75 53 64 6b 53 75 63 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}