rule Trojan_Win32_Qakbot_AY_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8b c7 f7 75 ?? 8a 04 0a 8b 55 ?? 32 04 17 88 04 3b 47 83 ee 01 75 } 		$a_01_1 = {51 6b 6b 62 61 6c } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}