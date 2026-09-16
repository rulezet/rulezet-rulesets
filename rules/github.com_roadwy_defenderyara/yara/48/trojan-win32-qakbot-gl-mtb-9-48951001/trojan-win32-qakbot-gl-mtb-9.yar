rule Trojan_Win32_Qakbot_GL_MTB_9{
	meta:
		description = "Trojan:Win32/Qakbot.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_02_0 = {8b ec 83 c4 e4 8d 45 fc 50 68 40 00 00 00 68 71 0c 00 00 68 61 40 0a 10 68 ff ff ff ff ff 15 ?? ?? ?? ?? 8b c5 8b e5 5d c3 } 		$a_02_1 = {81 e8 04 7a cc 8e 33 05 ?? ?? ?? ?? 2b c6 83 f0 6f 81 c0 7c f7 41 71 89 45 ?? e8 ?? ?? ?? ?? e8 } 		$a_00_2 = {34 1a 68 12 dc 09 10 c3 } 		$a_00_3 = {c0 c8 06 68 e1 0a 0a 10 c3 } 		$a_80_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*5+(#a_00_2  & 1)*3+(#a_00_3  & 1)*2+(#a_80_4  & 1)*1) >=21
 
}