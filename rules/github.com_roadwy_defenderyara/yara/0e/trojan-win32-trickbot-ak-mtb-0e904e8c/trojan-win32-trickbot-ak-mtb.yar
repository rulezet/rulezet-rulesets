rule Trojan_Win32_Trickbot_AK_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8b c1 f7 75 0c 8a 5c 0c 50 0f b6 c3 41 0f b6 14 3a 03 d6 03 c2 33 d2 be e2 ?? ?? ?? f7 f6 8b f2 8a 44 34 50 88 44 0c 4f 88 5c 34 50 81 f9 e2 90 1b 00 72 ca } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}