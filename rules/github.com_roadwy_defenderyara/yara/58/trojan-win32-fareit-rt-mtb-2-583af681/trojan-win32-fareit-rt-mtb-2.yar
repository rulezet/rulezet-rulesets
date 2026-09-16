rule Trojan_Win32_Fareit_RT_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {79 54 48 49 41 46 5a 6b 77 4f 30 35 35 52 4e 62 49 70 38 78 4d 36 7a 51 64 31 35 35 } 		$a_81_1 = {49 6e 74 65 72 76 61 6c 68 79 70 70 69 67 68 65 64 65 72 } 		$a_81_2 = {53 6b 75 6c 64 65 72 62 6c 61 64 65 74 73 31 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}