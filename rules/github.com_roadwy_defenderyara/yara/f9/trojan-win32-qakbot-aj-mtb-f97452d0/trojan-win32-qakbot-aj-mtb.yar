rule Trojan_Win32_Qakbot_AJ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 45 e0 89 45 dc 8b 45 f0 03 45 e0 89 45 f0 8b 45 ec 2b 45 e0 89 45 ec 83 7d e0 00 76 90 0a 50 00 ff 75 ?? ff 75 ?? 8b 45 ?? 8b 40 ?? 8b 4d ?? 8b 00 8b 49 ?? ff 50 ?? 89 45 ?? 8b 45 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}