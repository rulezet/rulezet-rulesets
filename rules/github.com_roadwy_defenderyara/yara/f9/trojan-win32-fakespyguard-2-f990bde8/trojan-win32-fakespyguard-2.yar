rule Trojan_Win32_FakeSpyguard_2{
	meta:
		description = "Trojan:Win32/FakeSpyguard,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c 50 72 6f 74 65 63 74 5c } 		$a_01_1 = {73 68 6c 63 6f 6e 66 2e 64 61 74 } 		$a_01_2 = {72 6d 6c 69 73 74 2e 64 61 74 } 		$a_01_3 = {53 65 63 75 72 69 74 79 33 32 5f 77 69 6e } 		$a_01_4 = {72 74 69 6d 65 2e 64 61 74 } 	condition:
		((#a_00_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}