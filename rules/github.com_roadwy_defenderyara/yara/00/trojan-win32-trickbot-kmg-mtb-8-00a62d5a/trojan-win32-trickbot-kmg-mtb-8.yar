rule Trojan_Win32_Trickbot_KMG_MTB_8{
	meta:
		description = "Trojan:Win32/Trickbot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {33 c0 3b fb 7e ?? 8b 54 24 ?? 8d 4c 3a ?? 8b ff 8a 11 88 ?? ?? ?? ?? ?? 40 49 3b c7 7c ?? 8d 47 01 83 f8 3e 88 9f ?? ?? ?? ?? 7d } 		$a_00_1 = {23 6f 71 34 34 64 32 3f 45 31 41 56 31 30 6b } 		$a_00_2 = {53 74 75 70 20 77 69 6e 64 6f 77 73 20 64 65 66 65 6e 64 65 72 20 68 61 68 61 68 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}