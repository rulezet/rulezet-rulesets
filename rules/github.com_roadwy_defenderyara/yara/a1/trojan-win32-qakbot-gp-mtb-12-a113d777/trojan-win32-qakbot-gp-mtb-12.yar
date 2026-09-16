rule Trojan_Win32_Qakbot_GP_MTB_12{
	meta:
		description = "Trojan:Win32/Qakbot.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_02_0 = {57 c7 45 ec 0e dc eb d2 3a d2 74 00 81 6d ec c4 00 00 00 e8 ?? ?? ?? ?? 66 3b c9 74 } 		$a_00_1 = {ff 75 0c ff 75 08 eb 00 ff 55 f8 } 		$a_00_2 = {ff 75 b0 ff 55 f0 3a d2 74 } 		$a_80_3 = {34 66 33 66 39 62 30 35 30 30 65 63 61 65 30 38 30 30 30 30 30 30 30 30 38 30 34 38 38 62 63 34 34 38 38 39 35 38 30 38 34 63 38 39 34 38 } 		$a_00_4 = {c6 45 ba 53 80 45 ba 19 66 3b f6 74 } 		$a_00_5 = {c6 45 be 59 80 45 be 10 3a c9 74 } 	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_80_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=15
 
}