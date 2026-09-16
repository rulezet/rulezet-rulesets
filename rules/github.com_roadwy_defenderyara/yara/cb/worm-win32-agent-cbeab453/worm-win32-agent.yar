rule Worm_Win32_Agent{
	meta:
		description = "Worm:Win32/Agent,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 79 73 74 65 6d 20 73 79 73 20 70 72 6f 63 65 73 73 2e 65 78 65 } 		$a_01_1 = {77 69 6e 64 6f 77 73 5c 57 69 6e 64 6f 77 73 20 4d 65 64 6f 63 5c } 		$a_01_2 = {77 69 6e 64 6f 77 73 5f 64 78 67 63 2e 65 78 65 } 		$a_01_3 = {43 3a 5c 00 44 3a 5c 00 45 3a 5c 00 46 3a 5c 00 47 3a 5c 00 48 3a 5c 00 6b 3a 5c 00 52 3a 5c 00 53 3a 5c 00 54 3a 5c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}