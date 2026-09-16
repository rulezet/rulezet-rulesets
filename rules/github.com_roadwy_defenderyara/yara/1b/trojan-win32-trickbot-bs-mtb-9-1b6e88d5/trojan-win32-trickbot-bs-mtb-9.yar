rule Trojan_Win32_Trickbot_BS_MTB_9{
	meta:
		description = "Trojan:Win32/Trickbot.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b de 2b da 3b d8 72 ?? ff 15 ?? ?? ?? ?? 8b c3 eb ?? ff 15 ?? ?? ?? ?? 8b 0f 8b 51 ?? 66 0f b6 1c 02 2b 5d ?? 66 85 db 7d ?? 81 c3 00 01 00 00 85 c9 74 ?? 66 83 39 01 75 1c 8b 51 ?? 8b 41 ?? 2b f2 3b f0 72 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}