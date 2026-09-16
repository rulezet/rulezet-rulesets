rule Trojan_Win32_Qakbot_GA_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_00_0 = {ac 68 04 f1 07 10 c3 } 		$a_00_1 = {34 43 68 f8 a5 08 10 c3 } 		$a_00_2 = {68 8a d6 07 10 68 8a d6 07 10 b8 69 2c 08 10 ff d0 } 		$a_80_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } 		$a_80_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 } 	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=16
 
}