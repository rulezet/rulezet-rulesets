rule Trojan_Win32_Qakbot_GK_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {fc f3 a4 57 c7 04 e4 [0-04] 59 89 7d ?? 33 7d ?? 0b bb [0-04] 83 e0 00 31 f8 8b 7d ?? 68 [0-04] 8f 83 [0-04] 21 8b [0-04] 89 4d ?? 8b 8b [0-04] 01 c1 51 8b 4d ?? 58 ff e0 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}