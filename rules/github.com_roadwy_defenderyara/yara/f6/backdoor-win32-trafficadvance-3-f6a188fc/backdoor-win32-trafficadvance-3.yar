rule Backdoor_Win32_Trafficadvance_3{
	meta:
		description = "Backdoor:Win32/Trafficadvance,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 74 72 61 66 66 69 63 61 64 76 61 6e 63 65 2e 6e 65 74 } 		$a_01_1 = {20 61 64 20 49 6e 74 65 72 6e 65 74 } 		$a_01_2 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 51 75 69 63 6b 20 4c 61 75 6e 63 68 } 		$a_01_3 = {52 43 46 2e 25 68 64 2e 25 68 64 7c 4d 6f 44 2e 25 68 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}