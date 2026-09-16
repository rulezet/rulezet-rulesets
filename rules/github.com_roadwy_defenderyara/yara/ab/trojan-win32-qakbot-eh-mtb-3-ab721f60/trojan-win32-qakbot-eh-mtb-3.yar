rule Trojan_Win32_Qakbot_EH_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 12 03 55 a8 2b d0 8b 45 d8 89 10 6a 00 e8 ?? ?? ?? ?? 8b 55 c4 03 55 a4 2b d0 89 55 a0 6a 00 e8 ?? ?? ?? ?? 8b 55 a0 2b d0 8b 45 d8 33 10 } 	condition:
		((#a_03_0  & 1)*4) >=4
 
}