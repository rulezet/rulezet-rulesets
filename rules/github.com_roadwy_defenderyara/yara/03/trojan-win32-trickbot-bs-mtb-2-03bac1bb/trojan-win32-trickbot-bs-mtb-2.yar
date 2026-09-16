rule Trojan_Win32_Trickbot_BS_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 00 ff d6 8b 45 fc 0f b6 4d 17 0f b6 84 05 ?? ?? ?? ?? 03 c1 8b cb 99 f7 f9 8b 45 08 8a 8c 15 ?? ?? ?? ?? 30 08 40 ff 4d f8 89 45 08 0f 85 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}