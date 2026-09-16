rule Trojan_Win32_Qakbot_GO_MTB_9{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 55 fc 89 55 ?? 0f b6 05 [0-04] 03 45 ?? 89 45 ?? 0f b6 0d [0-04] 8b 55 ?? 2b d1 89 55 ?? 0f b6 05 [0-04] 33 45 ?? 89 45 ?? 0f b6 0d [0-04] 8b 55 ?? 2b d1 89 55 ?? 0f b6 05 [0-04] 8b 4d ?? 2b c8 89 4d ?? 8b 15 [0-04] 03 55 ?? 8a 45 ?? 88 02 e9 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}