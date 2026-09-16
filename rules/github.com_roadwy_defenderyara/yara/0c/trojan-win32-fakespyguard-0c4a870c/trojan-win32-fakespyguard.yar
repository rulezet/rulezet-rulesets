rule Trojan_Win32_FakeSpyguard{
	meta:
		description = "Trojan:Win32/FakeSpyguard,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 72 61 63 6b 5f 69 64 3d 25 64 00 } 		$a_01_1 = {73 76 68 6f 73 74 2e 65 78 65 00 } 		$a_01_2 = {43 54 45 4d 4f 4e 2e 45 58 45 00 } 		$a_01_3 = {53 70 79 77 61 72 65 20 47 75 61 72 64 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}