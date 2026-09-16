rule Trojan_Win32_Qakbot_GM_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c7 04 e4 ff ff 0f 00 59 6a 00 89 3c [0-01] 31 ff 0b bb [0-04] 89 f8 5f 50 c7 04 e4 [0-04] 8f 83 [0-04] 21 8b [0-04] 6a 00 31 34 [0-01] 50 5e 03 b3 [0-04] 89 f0 5e ff e0 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}