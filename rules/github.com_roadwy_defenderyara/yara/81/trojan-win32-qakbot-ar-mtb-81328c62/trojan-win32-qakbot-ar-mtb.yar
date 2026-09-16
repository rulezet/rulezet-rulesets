rule Trojan_Win32_Qakbot_AR_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4d f4 8b 55 fc 8d 84 0a 59 11 00 00 89 45 f0 8b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 55 f0 89 15 ?? ?? ?? ?? 8b 45 fc } 	condition:
		((#a_02_0  & 1)*2) >=2
 
}