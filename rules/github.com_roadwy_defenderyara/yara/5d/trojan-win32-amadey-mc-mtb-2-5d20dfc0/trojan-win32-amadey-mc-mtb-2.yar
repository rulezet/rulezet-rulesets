rule Trojan_Win32_Amadey_MC_MTB_2{
	meta:
		description = "Trojan:Win32/Amadey.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 d0 c3 42 00 e8 35 7e 01 00 59 c3 cc cc cc cc 68 70 c3 42 00 e8 25 7e 01 00 59 c3 cc cc cc cc 6a 20 68 cc 53 43 00 b9 74 bb 43 00 e8 } 		$a_01_1 = {41 6d 61 64 65 79 2e 70 64 62 } 		$a_01_2 = {43 72 65 61 74 65 4d 75 74 65 78 57 } 		$a_03_3 = {3a 5c 54 45 4d 50 5c [0-25] 5c 67 68 61 61 65 72 2e 65 78 65 } 		$a_01_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_03_3  & 1)*2+(#a_01_4  & 1)*1) >=9
 
}