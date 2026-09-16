rule Trojan_Win32_Trickbot_SX_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {57 8b 4d 00 8b fb 8b 51 0c 8b 59 14 2b d3 03 d6 66 0f b6 0a 8b d9 2b cf 66 85 c9 7d ?? 81 c1 00 01 00 00 46 88 0a 3b f0 7e } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}