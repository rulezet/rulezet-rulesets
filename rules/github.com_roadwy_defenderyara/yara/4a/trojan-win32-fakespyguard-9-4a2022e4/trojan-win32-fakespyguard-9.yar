rule Trojan_Win32_FakeSpyguard_9{
	meta:
		description = "Trojan:Win32/FakeSpyguard,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 65 63 75 72 69 74 79 33 32 5f 77 69 6e 00 00 53 70 79 77 61 72 65 20 47 75 61 72 64 20 32 30 30 38 } 		$a_01_1 = {50 72 6f 6a 65 63 74 31 2e 64 6c 6c 00 53 65 74 48 6f 6f 6b } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}