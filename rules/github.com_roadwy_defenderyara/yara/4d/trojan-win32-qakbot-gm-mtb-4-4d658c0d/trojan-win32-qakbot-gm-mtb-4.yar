rule Trojan_Win32_Qakbot_GM_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 [0-19] 33 [0-03] c7 05 [0-04] 00 00 00 00 [0-06] 01 [0-05] a1 [0-04] 8b 0d [0-04] 89 08 ?? 5d c3 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}