rule TrojanDropper_Win32_AceLog_B_dha_2{
	meta:
		description = "TrojanDropper:Win32/AceLog.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b7 8c 05 ?? ?? ff ff 66 31 8c 05 ?? ?? ff ff 0f b7 8c 05 ?? ?? ff ff 66 31 8c 05 ?? ?? ff ff 0f b7 8c 05 ?? ?? ff ff 66 31 8c 05 ?? ?? ff ff 0f b7 8c 05 ?? ?? ff ff 66 31 8c 05 ?? ?? ff ff 83 c0 08 3d 00 01 00 00 72 b6 } 		$a_03_1 = {0f b7 84 0d ?? ?? ff ff 66 31 84 0d ?? ?? ff ff 0f b7 84 0d ?? ?? ff ff 66 31 84 0d ?? ?? ff ff 0f b7 84 0d ?? ?? ff ff 66 31 84 0d ?? ?? ff ff 0f b7 84 0d ?? ?? ff ff 66 31 84 0d ?? ?? ff ff 83 c1 08 81 f9 00 01 00 00 72 b5 } 		$a_03_2 = {63 6d 64 20 2f ?? 20 44 45 4c 20 00 20 22 00 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*10) >=11
 
}