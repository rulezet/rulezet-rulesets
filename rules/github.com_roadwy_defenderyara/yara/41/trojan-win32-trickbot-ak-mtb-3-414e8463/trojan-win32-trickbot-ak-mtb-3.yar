rule Trojan_Win32_Trickbot_AK_MTB_3{
	meta:
		description = "Trojan:Win32/Trickbot.AK!MTB!!Trickbot.AK!MTB,SIGNATURE_TYPE_ARHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_81_0 = {70 77 67 72 61 62 } 		$a_81_1 = {2f 25 73 2f 25 73 2f 35 2f 25 73 2f } 		$a_81_2 = {2f 35 2f 73 70 6b 2f } 		$a_81_3 = {6d 63 63 6f 6e 66 } 		$a_81_4 = {61 75 74 6f 72 75 6e } 		$a_81_5 = {31 38 36 2e 37 31 2e 31 35 30 2e 32 33 } 	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=7
 
}