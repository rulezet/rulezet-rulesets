rule Trojan_Win32_Qbot_RB_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 d8 8b 1a 03 5d a8 2b d8 4b 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 03 d8 8b 45 d8 89 18 8b 45 c4 03 45 a4 89 45 a0 6a 00 e8 ?? ?? ?? ?? 8b 55 a0 2b d0 4a 8b 45 d8 33 10 89 55 a0 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}