rule Trojan_Win32_Trickbot_SK_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_02_0 = {59 59 ff d7 c6 45 b7 01 eb ?? 55 8b ec 51 53 8b 1d ?? ?? ?? ?? 56 57 33 c0 } 		$a_02_1 = {8b fa 8d 84 3d ?? ?? ff ff 8a 10 88 16 88 18 0f b6 06 0f b6 d3 03 c2 99 8b f1 f7 fe 8b 85 ?? ?? ff ff 8a 94 15 ?? ?? ff ff 30 10 40 83 bd ?? ?? ff ff 00 89 85 ?? ?? ff ff 75 } 	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=4
 
}