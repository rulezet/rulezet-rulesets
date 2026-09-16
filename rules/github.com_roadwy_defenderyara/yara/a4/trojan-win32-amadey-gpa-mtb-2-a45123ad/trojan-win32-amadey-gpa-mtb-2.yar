rule Trojan_Win32_Amadey_GPA_MTB_2{
	meta:
		description = "Trojan:Win32/Amadey.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4a 4d 66 49 56 5a 4c 43 79 46 33 46 4a 74 73 42 4b 46 31 56 4b 64 71 } 		$a_01_1 = {65 71 4e 76 51 42 6e 71 4f 78 78 36 } 		$a_01_2 = {4b 46 31 46 51 52 6e 6a 66 45 4a 36 4a 33 4b 48 79 75 43 } 		$a_01_3 = {57 33 31 48 4d 41 34 7a 57 69 4b 32 52 59 65 63 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}