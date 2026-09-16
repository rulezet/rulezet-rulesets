rule Trojan_Win32_Zusy_NZ_MTB_5{
	meta:
		description = "Trojan:Win32/Zusy.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {89 41 08 c7 41 04 00 00 00 00 89 51 0c 8b 06 89 41 10 8b 45 f8 89 0e ff 00 ff 75 fc ff d3 8b 77 50 6a 20 } 		$a_01_1 = {47 65 74 4e 61 74 69 76 65 53 79 73 74 65 6d 49 6e 66 6f } 		$a_01_2 = {57 53 41 53 65 6e 64 } 		$a_01_3 = {3a 4a 3a 4f 3a 58 3a 56 3a 53 3a 59 3a } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}