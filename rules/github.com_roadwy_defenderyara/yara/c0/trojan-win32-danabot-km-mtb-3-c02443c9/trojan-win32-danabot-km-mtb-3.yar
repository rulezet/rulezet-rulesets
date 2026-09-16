rule Trojan_Win32_Danabot_KM_MTB_3{
	meta:
		description = "Trojan:Win32/Danabot.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 03 55 ?? 89 55 ?? 8b 45 ?? 31 45 ?? 2b 75 ?? 8b 45 ?? d1 6d ?? 29 45 ?? ff 4d ?? 0f 85 } 	condition:
		((#a_02_0  & 1)*2) >=2
 
}