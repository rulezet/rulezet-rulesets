rule Trojan_Win32_Trickbot_PB_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {54 72 39 6a 6e 58 79 35 52 23 4b 7b 71 7a 6b } 		$a_00_1 = {64 75 7a 24 45 23 6b 51 25 65 74 49 71 30 46 2a 39 55 4e 76 48 66 46 72 4d 51 } 		$a_02_2 = {8a 00 88 c1 8b 45 ?? 8b 9c ?? ?? ?? ?? ?? 8b 45 ?? 8b 84 ?? ?? ?? ?? ?? 01 d8 25 ff 00 00 80 85 c0 79 ?? 48 0d 00 ff ff ff 40 8b 84 ?? ?? ?? ?? ?? 31 c8 88 02 ff 45 ?? 8b 45 ?? 3b 45 ?? 0f 92 c0 84 c0 0f 85 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}