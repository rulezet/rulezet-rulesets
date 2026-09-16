rule Trojan_Win32_Zusy_EC_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 4f 52 4b 5f 32 30 31 36 30 33 32 38 31 37 35 36 30 30 37 36 31 39 34 33 } 		$a_01_1 = {63 3a 5c 5c 44 65 73 74 72 6f } 		$a_81_2 = {6f 74 68 69 6e 66 } 		$a_81_3 = {4e 6b 47 79 56 69 41 4a 6b 77 48 69 4c 47 } 		$a_81_4 = {41 4a 6b 77 48 69 4c 47 59 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}