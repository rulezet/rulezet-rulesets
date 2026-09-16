rule Trojan_Win32_Qakbot_GD_MTB_9{
	meta:
		description = "Trojan:Win32/Qakbot.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 06 00 00 "
		
	strings :
		$a_02_0 = {c7 85 6c ff ff ff ?? ?? ?? ?? c7 85 6c ff ff ff ?? ?? ?? ?? c7 85 6c ff ff ff ?? ?? ?? ?? c7 85 6c ff ff ff ?? ?? ?? ?? c7 85 6c ff ff ff ?? ?? ?? ?? c7 85 6c ff ff ff ?? ?? ?? ?? c7 85 6c ff ff ff ?? ?? ?? ?? c7 85 6c ff ff ff } 		$a_02_1 = {03 f0 8b 45 08 03 30 8b 4d 08 89 31 [0-14] 8b 55 08 8b ?? 2b ?? 8b 55 08 89 ?? 5e 8b e5 5d c3 } 		$a_00_2 = {68 00 5a 00 54 00 44 00 4b 00 54 00 64 00 4a 00 4e 00 53 00 } 		$a_80_3 = {4c 6f 61 64 43 75 72 73 6f 72 46 72 6f 6d 46 69 6c 65 57 } 		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } 		$a_80_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*10+(#a_80_3  & 1)*10+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=41
 
}