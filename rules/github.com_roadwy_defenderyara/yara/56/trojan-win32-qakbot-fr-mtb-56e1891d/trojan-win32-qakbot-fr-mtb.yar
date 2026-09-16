rule Trojan_Win32_Qakbot_FR_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.FR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 83 e0 ?? 8a 04 10 32 04 1f 88 04 39 47 83 ee ?? 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}