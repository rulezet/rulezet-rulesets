rule Trojan_Win32_Qakbot_GM_MTB_8{
	meta:
		description = "Trojan:Win32/Qakbot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {fc f3 a4 50 c7 04 e4 ff ff 0f 00 59 89 75 [0-01] 33 75 [0-01] 33 b3 [0-04] 83 e0 00 09 f0 8b 75 [0-01] 68 [0-04] 8f 83 [0-04] 21 8b [0-04] 51 8b 8b [0-04] 50 8f 45 [0-01] 01 4d [0-01] ff 75 [0-01] 58 59 ff e0 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}