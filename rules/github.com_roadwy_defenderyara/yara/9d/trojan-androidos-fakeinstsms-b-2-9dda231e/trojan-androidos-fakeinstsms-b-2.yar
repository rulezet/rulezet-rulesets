rule Trojan_AndroidOS_FakeInstSms_B_2{
	meta:
		description = "Trojan:AndroidOS/FakeInstSms.B,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e1 0d 0a 10 49 0e 13 11 b7 ed 8e dd 50 0d 13 11 28 f2 0d 0d 28 e8 49 0d 13 11 b7 ad 8e dd 50 0d 13 11 28 e9 e1 0d 09 10 49 0e 13 11 b7 ed 8e dd 50 0d 13 11 28 e0 49 0d 13 11 b7 9d 8e dd 50 0d 13 11 28 d9 e1 0d 08 10 49 0e 13 11 b7 ed 8e dd 50 0d 13 11 28 d0 } 		$a_00_1 = {4c 63 6f 6d 2f 61 6e 64 72 6f 69 64 73 2f 75 70 64 61 74 65 2f 52 65 63 3b } 	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}