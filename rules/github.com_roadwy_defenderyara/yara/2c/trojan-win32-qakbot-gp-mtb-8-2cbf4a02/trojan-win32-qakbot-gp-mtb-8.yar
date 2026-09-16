rule Trojan_Win32_Qakbot_GP_MTB_8{
	meta:
		description = "Trojan:Win32/Qakbot.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 05 00 00 "
		
	strings :
		$a_02_0 = {ff 75 fc ff 75 f8 ff 75 f0 ff 75 f4 ff 35 ?? ?? ?? ?? 6a 01 ff 90 0a 30 00 8b ?? ?? 03 ?? ?? 89 ?? ?? 83 ?? ?? 04 81 ?? ?? 00 10 00 00 } 		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } 		$a_00_2 = {99 03 04 24 13 54 24 04 83 c4 08 } 		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } 		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } 	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_00_2  & 1)*3+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=19
 
}