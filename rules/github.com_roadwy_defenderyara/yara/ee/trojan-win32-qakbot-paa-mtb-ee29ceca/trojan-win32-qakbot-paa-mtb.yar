rule Trojan_Win32_Qakbot_PAA_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {89 55 fc 8b 45 fc c1 f8 02 89 45 fc 8b 55 fc 2b 55 10 03 55 fc 8b 4d fc d3 fa 8b 4d fc d3 fa 8b 0d 24 fe 05 10 0f af 0d 8c fd 05 10 a1 d0 fd 05 10 d3 f8 8b 4d 14 d3 e0 33 d0 8b 45 fc 2b 45 08 8b 4d fc 03 4d 18 03 4d 20 03 4d 08 d3 e0 8b 4d fc d3 e0 } 		$a_03_1 = {8b 0d 28 fe 05 10 d3 e2 33 c2 8b 55 fc 2b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 0d 44 fe 05 10 d3 e2 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}