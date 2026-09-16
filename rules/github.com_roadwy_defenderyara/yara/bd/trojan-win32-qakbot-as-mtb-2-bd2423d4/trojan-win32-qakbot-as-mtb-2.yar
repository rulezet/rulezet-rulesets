rule Trojan_Win32_Qakbot_AS_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3d 5f 1d 00 00 77 ?? 40 89 45 ?? 3b [0-02] 72 90 0a 20 00 85 c0 74 ?? ff 15 ?? ?? ?? ?? 8b 45 } 		$a_03_1 = {0f b6 04 39 33 f0 8b c6 c1 ee 04 83 e0 0f 33 34 85 ?? ?? ?? ?? 8b c6 c1 ee 04 83 e0 0f 33 34 85 ?? ?? ?? ?? 41 3b ca 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}