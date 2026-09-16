rule Trojan_Win32_Qakbot_GA_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c1 2b c3 83 c0 ?? a3 [0-04] 8b 06 05 [0-04] 89 06 83 c6 04 a3 [0-04] 0f b6 c1 66 03 05 [0-04] 66 03 c2 89 74 24 ?? 66 03 44 24 ?? 8b f2 66 03 f8 83 6c 24 ?? 01 66 89 7c 24 ?? 0f 85 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}