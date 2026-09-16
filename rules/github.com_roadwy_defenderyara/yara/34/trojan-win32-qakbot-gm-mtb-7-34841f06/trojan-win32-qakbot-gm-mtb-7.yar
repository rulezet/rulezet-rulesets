rule Trojan_Win32_Qakbot_GM_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c7 04 e4 ff ff 0f 00 59 89 75 [0-01] 31 f6 0b b3 [0-04] 89 f0 8b 75 [0-01] 68 [0-04] 8f 83 [0-04] 21 8b [0-04] 52 8b 93 [0-04] 50 8f 45 [0-01] 01 55 [0-01] ff 75 [0-01] 58 5a ff e0 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}