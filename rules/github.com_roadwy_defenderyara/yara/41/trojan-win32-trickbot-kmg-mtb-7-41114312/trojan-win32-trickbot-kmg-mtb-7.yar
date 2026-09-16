rule Trojan_Win32_Trickbot_KMG_MTB_7{
	meta:
		description = "Trojan:Win32/Trickbot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {33 f6 3b fb 7e ?? 8d 87 ?? ?? ?? ?? 8a 08 88 8e ?? ?? ?? ?? 46 48 3b f7 7c ?? 8d 47 ?? 83 f8 3e 88 9f ?? ?? ?? ?? 7d } 		$a_00_1 = {45 53 45 54 20 68 79 75 6e 79 61 } 		$a_00_2 = {62 29 58 21 51 4d 42 4a 49 5f 78 54 41 76 4a } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}