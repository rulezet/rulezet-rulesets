rule Trojan_Win32_Virtumonde_M_2{
	meta:
		description = "Trojan:Win32/Virtumonde.M,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 74 61 72 74 77 61 74 63 68 65 72 } 		$a_01_1 = {73 79 73 74 65 6d 32 2e 64 6c 6c 00 77 61 74 63 68 64 6c 6c 2e 64 6c 6c } 		$a_01_2 = {64 3a 5c 23 64 65 76 65 6c 6f 70 6d 65 6e 74 5c 5f 5f 74 61 73 6b 73 5c 57 61 74 63 68 65 72 5f 62 75 6e 64 6c 65 5c } 		$a_01_3 = {77 61 74 63 68 65 72 5f 62 75 6e 64 6c 65 2e 64 6c 6c 00 53 74 61 72 74 75 70 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}