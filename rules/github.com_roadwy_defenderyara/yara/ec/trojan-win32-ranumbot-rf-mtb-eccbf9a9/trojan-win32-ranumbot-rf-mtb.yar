rule Trojan_Win32_Ranumbot_RF_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c4 89 84 24 ?? ?? ?? ?? 56 33 f6 85 ff 7e ?? 55 8b 2d ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 33 83 ff 19 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}