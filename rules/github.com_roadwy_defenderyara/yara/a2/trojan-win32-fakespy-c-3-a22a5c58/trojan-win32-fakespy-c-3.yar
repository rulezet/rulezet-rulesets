rule Trojan_Win32_Fakespy_C_3{
	meta:
		description = "Trojan:Win32/Fakespy.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {69 6e 73 74 72 75 63 74 69 6f 6e 73 54 65 78 74 33 22 3e 43 6c 69 63 6b } 		$a_01_1 = {6a 61 76 61 73 63 72 69 70 74 3a 52 75 6e 41 6e 74 69 76 69 72 75 73 28 29 } 		$a_01_2 = {62 6c 6f 63 6b 65 64 20 66 6f 72 65 76 65 72 2e 3c 2f 62 3e 3c 62 72 3e } 		$a_01_3 = {70 75 67 61 6c 6b 61 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}