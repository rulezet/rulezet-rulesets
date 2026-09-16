rule Trojan_Win32_TrickBot_RT_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 c0 3b eb 7e ?? 8b 54 24 ?? 8d 4c 2a ?? 8a 11 88 ?? ?? ?? ?? ?? 40 49 3b c5 7c ?? 8d 45 ?? 83 f8 3e 88 9d ?? ?? ?? ?? 7d } 		$a_01_1 = {3f 6f 47 62 21 64 6f 24 50 62 23 2b 69 51 4a } 	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}