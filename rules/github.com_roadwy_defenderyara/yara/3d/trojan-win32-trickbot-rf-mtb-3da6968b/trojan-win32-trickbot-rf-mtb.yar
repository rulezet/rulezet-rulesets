rule Trojan_Win32_Trickbot_RF_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b df 2b da 3b d9 72 ?? ff 15 ?? ?? ?? ?? eb ?? ff 15 ?? ?? ?? ?? 8b d8 8d 45 ?? 50 ff 15 ?? ?? ?? ?? 8b 0e 8b 51 0c 88 04 1a b8 01 00 00 00 03 c7 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}