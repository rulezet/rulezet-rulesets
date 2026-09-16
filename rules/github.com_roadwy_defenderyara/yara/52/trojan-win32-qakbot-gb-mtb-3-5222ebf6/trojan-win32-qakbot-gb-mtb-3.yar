rule Trojan_Win32_Qakbot_GB_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b7 f3 02 c6 02 c2 0f b6 c0 6b c0 ?? 2b f0 89 35 [0-04] 8a 15 [0-04] 8d 87 [0-04] 8b 7c 24 ?? 8a f3 80 c2 ?? a3 [0-04] 02 d6 8a 35 [0-04] 89 07 83 c7 04 83 6c 24 ?? 01 89 7c 24 ?? 0f 85 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}