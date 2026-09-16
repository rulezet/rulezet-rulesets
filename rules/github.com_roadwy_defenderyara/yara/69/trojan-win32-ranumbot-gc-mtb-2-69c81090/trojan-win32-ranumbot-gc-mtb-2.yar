rule Trojan_Win32_Ranumbot_GC_MTB_2{
	meta:
		description = "Trojan:Win32/Ranumbot.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c1 01 89 4d ?? 8b 55 ?? 8b 45 ?? 3b 82 ?? ?? ?? ?? 73 ?? 8b 4d ?? 03 4d ?? 0f b6 11 8b 45 ?? 03 45 ?? 0f b6 08 33 ?? 8b 55 ?? 03 55 ?? 88 0a } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}