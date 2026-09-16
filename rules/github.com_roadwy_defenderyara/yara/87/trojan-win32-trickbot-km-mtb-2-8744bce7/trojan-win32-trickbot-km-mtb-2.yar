rule Trojan_Win32_Trickbot_KM_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {33 c0 3b fb 7e ?? 8b 54 24 ?? 8d 4c 3a ?? 8a 11 88 ?? ?? ?? ?? ?? 40 49 3b c7 7c ?? 8d 47 ?? 83 f8 3e 88 9f ?? ?? ?? ?? 7d } 		$a_00_1 = {45 53 45 54 20 68 79 75 6e 79 61 } 		$a_00_2 = {66 43 30 29 47 76 54 57 53 6a 6d 2a 79 45 42 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}