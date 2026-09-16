rule Trojan_Win32_Zbot_EN_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {50 72 6f 78 79 2d 43 6f 6e 6e 65 63 74 69 6f 6e } 		$a_81_1 = {7c 7a 6b 72 76 76 63 6e 6d 61 65 62 4e 55 66 } 		$a_81_2 = {64 63 6d 5c 6e 5c 54 53 } 		$a_81_3 = {62 61 70 62 58 6c 55 52 } 		$a_81_4 = {66 62 6d 6e 58 5c 56 57 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}