rule Trojan_Win32_Qakbot_PA_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 75 f4 03 c6 03 45 f4 8b 0d ?? ?? ?? ?? 03 4d f4 03 4d f4 03 4d f4 8b 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 8a 04 06 88 04 0a 8b 0d ?? ?? ?? ?? 83 c1 01 89 0d } 		$a_01_1 = {03 f0 8b 55 08 8b 02 2b c6 8b 4d 08 89 01 5e 8b e5 5d c3 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}