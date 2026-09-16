rule Trojan_Win32_Qakbot_GQ_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_02_0 = {b8 73 16 00 00 ff 35 ?? ?? ?? ?? b8 73 16 00 00 ff 35 ?? ?? ?? ?? b8 73 16 00 00 ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? b8 01 00 00 00 50 ff 25 } 		$a_00_1 = {fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } 		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } 		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } 	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=16
 
}