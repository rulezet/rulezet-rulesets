rule Trojan_Win32_Trickbot_KMG_MTB_5{
	meta:
		description = "Trojan:Win32/Trickbot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 c0 3b df 7e ?? 8b 4c 24 ?? 8d 4c 19 ?? 8a 11 88 ?? ?? ?? ?? ?? 40 49 3b c3 7c ?? 8d 43 01 c6 83 ?? ?? ?? ?? 00 83 f8 3e 7d } 		$a_00_1 = {7a 31 3e 67 3e 61 55 66 51 2b 37 68 63 39 3e } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}