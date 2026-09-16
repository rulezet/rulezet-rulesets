rule Trojan_Win32_Qakbot_GO_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 00 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 03 55 ?? 33 ?? 03 d8 90 08 58 02 83 45 ?? 04 83 05 ?? ?? ?? ?? 04 8b 45 ?? 3b 05 } 		$a_80_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } 		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } 	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=11
 
}