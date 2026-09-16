rule Trojan_Win32_Trickbot_GKM_MTB_29{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b cb 8b f0 c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b cb 89 45 ?? c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 59 33 db 53 6a 01 53 89 45 ?? 53 8d 45 ?? 50 89 5d ?? ff d6 85 c0 75 } 		$a_00_1 = {45 53 45 54 20 68 79 75 6e 79 61 } 		$a_00_2 = {48 24 49 3c 4a 52 45 4a 2b 77 31 23 4d 2b 48 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}