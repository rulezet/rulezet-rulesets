rule Trojan_Win32_Trickbot_GKM_MTB_21{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c1 f7 35 ?? ?? ?? ?? 8b ea ff 15 ?? ?? ?? ?? 85 c0 74 ?? ff 15 ?? ?? ?? ?? 8a 14 2e 8b 44 24 ?? 8b 6c 24 ?? 8a 0c 28 32 ca 88 0c 28 8b 4c 24 ?? 40 3b c1 89 44 24 ?? 72 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}