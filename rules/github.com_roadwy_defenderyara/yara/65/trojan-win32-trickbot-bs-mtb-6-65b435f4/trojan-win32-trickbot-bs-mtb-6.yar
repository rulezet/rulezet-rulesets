rule Trojan_Win32_Trickbot_BS_MTB_6{
	meta:
		description = "Trojan:Win32/Trickbot.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {3b d8 72 10 ff 15 ?? ?? ?? ?? eb 08 ff 15 ?? ?? ?? ?? 8b d8 8b ?? ff 15 ?? ?? ?? ?? 8b [0-14] b8 01 00 00 00 03 c1 [0-06] 89 85 54 ff ff ff 8b ?? e9 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}