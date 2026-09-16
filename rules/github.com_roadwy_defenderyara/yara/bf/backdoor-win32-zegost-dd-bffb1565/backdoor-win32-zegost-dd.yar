rule Backdoor_Win32_Zegost_DD{
	meta:
		description = "Backdoor:Win32/Zegost.DD,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {4b 42 44 4c 6f 67 65 72 } 		$a_01_1 = {5b 45 58 45 43 55 54 45 5f 6b 65 79 5d } 		$a_00_2 = {47 6c 6f 62 61 6c 5c 61 69 72 6b 79 } 		$a_00_3 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 25 73 22 2c 48 69 67 68 53 79 73 74 65 6d } 	condition:
		((#a_00_0  & 1)*3+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}