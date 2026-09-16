rule Trojan_Win32_BrobanLaw_A{
	meta:
		description = "Trojan:Win32/BrobanLaw.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6c 00 76 00 65 00 70 00 61 00 65 00 61 00 6e 00 6a 00 66 00 62 00 73 00 6d 00 73 00 } 		$a_01_1 = {b8 01 02 00 00 e8 b0 94 e8 ff 05 ce 77 00 00 50 e8 f5 1c e9 ff e8 a8 64 ff ff 33 c0 5a 59 59 64 89 10 68 55 b2 57 00 c3 e9 4d ac e8 ff eb f8 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}