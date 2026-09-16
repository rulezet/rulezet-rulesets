rule Trojan_Win32_Trickbot_CM_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {32 5c 64 6c 6c 5c 52 65 6c 65 61 73 65 5c 54 65 73 74 30 31 2e 70 64 62 } 		$a_81_1 = {31 2e 64 6c 6c } 		$a_81_2 = {44 70 69 38 30 30 } 		$a_81_3 = {47 65 74 4d 6f 75 73 65 } 		$a_81_4 = {5b 20 47 4f 4f 44 20 5d } 		$a_03_5 = {6a 40 68 00 10 00 00 [0-06] 6a 00 ff d7 } 	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}