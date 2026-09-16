rule Trojan_Win32_Qakbot_EH_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 d8 8b 12 03 55 a8 2b d0 8b 45 d8 89 10 6a 00 e8 ?? ?? ?? ?? 8b 55 c4 03 55 a4 2b d0 89 55 a0 } 	condition:
		((#a_03_0  & 1)*3) >=3
 
}