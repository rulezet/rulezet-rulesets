rule Trojan_Win32_Wabot_GME_MTB{
	meta:
		description = "Trojan:Win32/Wabot.GME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 72 69 6a 75 61 6e 61 2e 74 78 74 } 		$a_01_1 = {71 55 46 44 5a 50 53 68 70 70 74 63 46 51 71 } 		$a_01_2 = {62 4b 44 50 6d 66 7a 68 65 70 55 51 5a 68 } 		$a_01_3 = {47 78 65 62 6b 34 4c 68 65 41 41 71 62 50 50 50 46 50 5a 50 5a 51 6b 24 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}