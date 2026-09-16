rule Trojan_Win32_Trickbot_VIS_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.VIS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 04 2e 88 04 33 88 0c 2e 0f b6 04 33 0f b6 c9 03 c1 33 d2 f7 35 ?? ?? ?? ?? 33 c9 33 c0 8b 44 24 10 8a 0c 38 8a 14 32 32 ca 88 0c 38 8b 4c 24 20 40 3b c1 89 44 24 10 72 a3 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}