rule Misleading_Win32_PerfectOptimizer_3{
	meta:
		description = "Misleading:Win32/PerfectOptimizer,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 00 57 00 65 00 73 00 6b 00 79 00 73 00 6f 00 66 00 74 00 5c 00 } 		$a_01_1 = {46 43 6f 6e 66 69 67 45 76 69 64 65 6e 63 65 53 63 61 6e 49 74 65 6d 73 } 		$a_01_2 = {46 43 6f 6e 66 69 67 52 65 67 53 63 61 6e 49 74 65 6d 73 } 		$a_01_3 = {46 43 6f 6e 66 69 67 51 75 69 63 6b 53 63 61 6e 49 74 65 6d 73 } 		$a_01_4 = {46 43 6f 6e 66 69 67 46 75 6c 6c 53 63 61 6e 49 74 65 6d 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}