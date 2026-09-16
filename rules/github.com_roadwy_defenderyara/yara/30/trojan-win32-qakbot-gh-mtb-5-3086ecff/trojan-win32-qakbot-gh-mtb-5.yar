rule Trojan_Win32_Qakbot_GH_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {fc f3 a4 50 c7 04 e4 ff ff 0f 00 59 89 55 ?? 2b 55 ?? 33 93 [0-04] 83 e0 00 31 d0 8b 55 ?? 53 c7 04 e4 [0-04] 8f 83 [0-04] 21 8b [0-04] 89 7d ?? 89 c7 03 bb [0-04] 57 8b 7d ?? 8f 83 [0-04] ff a3 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}