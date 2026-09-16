rule Trojan_Win32_Ranumbot_RTH_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c4 89 84 24 ?? ?? ?? ?? 56 33 f6 85 ff 7e ?? 55 8b 6c 24 ?? e8 ?? ?? ?? ?? 30 04 33 83 ff 19 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}