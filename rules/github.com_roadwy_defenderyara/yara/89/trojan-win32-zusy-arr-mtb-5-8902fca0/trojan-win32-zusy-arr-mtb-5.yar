rule Trojan_Win32_Zusy_ARR_MTB_5{
	meta:
		description = "Trojan:Win32/Zusy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 05 00 00 "
		
	strings :
		$a_03_0 = {48 8b d0 48 8b cb ff 15 ?? ?? ?? ?? 4c 89 64 24 30 44 89 64 24 28 4c 89 64 24 20 4c 8b cf 45 33 c0 33 d2 48 8b cb } 		$a_81_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 74 61 73 6b 6d 67 72 2e 65 78 65 20 2f 46 } 		$a_81_2 = {64 65 6c 20 2f 73 20 2f 71 20 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 } 		$a_81_3 = {72 69 63 6b 72 6f 6c 6c 2e 6a 70 67 } 		$a_81_4 = {49 44 52 5f 52 49 43 4b 52 4f 4c 4c 5f 4a 50 47 } 	condition:
		((#a_03_0  & 1)*3+(#a_81_1  & 1)*7+(#a_81_2  & 1)*10+(#a_81_3  & 1)*6+(#a_81_4  & 1)*4) >=30
 
}