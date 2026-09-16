rule Misleading_Win32_PerfectOptimizer_2{
	meta:
		description = "Misleading:Win32/PerfectOptimizer,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 00 69 00 72 00 61 00 63 00 6c 00 65 00 20 00 54 00 65 00 63 00 68 00 6e 00 6f 00 6c 00 6f 00 67 00 69 00 65 00 73 00 } 		$a_01_1 = {68 74 74 70 3a 2f 2f 36 37 2e 31 38 2e 31 31 31 2e 38 32 3a 38 30 38 38 } 		$a_01_2 = {5c 57 65 73 6b 79 73 6f 66 74 5c } 		$a_01_3 = {4c 69 63 65 6e 73 65 2e 44 4c 4c } 		$a_01_4 = {49 73 56 61 6c 69 64 53 4e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}