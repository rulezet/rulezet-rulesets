rule Trojan_Win32_Trickbot_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 35 ?? ?? ?? ?? 8d 45 ?? 0f af 05 ?? ?? ?? ?? 03 ea 03 c5 8b 6c 24 ?? 8a 14 08 8b 44 24 ?? 8a 1c 28 32 da 8b 54 24 ?? 88 1c 28 40 3b c2 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}