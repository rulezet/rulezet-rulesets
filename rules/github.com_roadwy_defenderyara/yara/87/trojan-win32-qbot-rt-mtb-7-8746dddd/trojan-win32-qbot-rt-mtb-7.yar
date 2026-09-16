rule Trojan_Win32_Qbot_RT_MTB_7{
	meta:
		description = "Trojan:Win32/Qbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 ?? c7 45 ?? 8a a5 08 00 8b 45 ?? 3b 45 ?? 0f } 		$a_03_1 = {03 d8 68 69 23 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 69 23 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 6a 00 e8 ?? ?? ?? ?? 6a } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}