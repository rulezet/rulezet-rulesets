rule Trojan_Win32_Qakbot_GF_MTB_8{
	meta:
		description = "Trojan:Win32/Qakbot.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {29 c9 09 c1 89 8b [0-04] 8b 4d ?? 8f 45 ?? 8b 4d ?? f3 a4 b9 ff ff [0-02] 89 4d ?? 31 c9 33 8b [0-04] 89 c8 8b 4d ?? 56 c7 04 [0-05] 8f 83 [0-04] 21 8b [0-04] 57 8b bb [0-04] 50 8f 45 ?? 01 7d ?? ff 75 ?? 58 5f ff e0 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}