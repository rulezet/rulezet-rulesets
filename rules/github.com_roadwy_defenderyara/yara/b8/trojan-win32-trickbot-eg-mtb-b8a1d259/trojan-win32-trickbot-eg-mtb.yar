rule Trojan_Win32_Trickbot_EG_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 f7 fd 89 d1 8b 7c 94 ?? 8d 04 1f 99 f7 fd 89 d3 8b 44 ?? ?? 89 44 ?? ?? 89 fa 0f b6 c2 89 44 ?? ?? 03 44 ?? ?? 99 f7 fd 8b 44 ?? ?? 8b 54 ?? ?? 30 04 32 46 81 fe ?? ?? ?? ?? 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}