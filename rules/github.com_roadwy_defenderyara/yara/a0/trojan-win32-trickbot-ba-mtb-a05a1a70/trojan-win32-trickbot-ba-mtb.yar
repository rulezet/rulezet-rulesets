rule Trojan_Win32_Trickbot_BA_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c1 8b cb 99 f7 f9 8b 4d ?? 8b 75 ?? 0f be 0c 31 51 0f b6 04 3a 50 e8 ?? ?? ?? ?? 83 c4 10 88 06 46 ff 4d ?? 89 75 ?? 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}