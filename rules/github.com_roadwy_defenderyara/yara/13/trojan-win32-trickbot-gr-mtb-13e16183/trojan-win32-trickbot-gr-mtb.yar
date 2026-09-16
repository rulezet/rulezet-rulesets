rule Trojan_Win32_Trickbot_GR_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 73 0c 03 f7 8b ea 3b e9 76 [0-07] 8b 44 24 14 83 78 18 ?? 72 ?? 83 c0 ?? 8b 00 eb ?? 83 c0 ?? 8a 0c 28 30 0e 8b 43 10 2b 43 0c 47 3b f8 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}