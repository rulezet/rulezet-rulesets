rule Trojan_Win32_Trickbot_RM_MTB_5{
	meta:
		description = "Trojan:Win32/Trickbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 "
		
	strings :
		$a_03_0 = {89 45 e8 c7 45 ?? 42 00 00 00 e8 ?? ?? ?? ?? 8b 4d ?? 85 c9 76 ?? 8b 45 ?? 8d a4 24 ?? ?? ?? ?? 8a 10 80 f2 63 80 c2 63 88 10 83 c0 01 83 e9 01 75 } 		$a_81_1 = {42 5a 59 54 59 2e 70 6e 67 } 		$a_81_2 = {4f 4c 45 41 43 43 2e 64 6c 6c } 		$a_81_3 = {47 65 74 53 79 73 74 65 6d 49 6e 66 6f } 		$a_81_4 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } 	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*5+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=18
 
}