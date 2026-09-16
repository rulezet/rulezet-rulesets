rule Trojan_Win32_Trickbot_KMG_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c6 99 f7 f9 0f b6 04 2b 8b f2 8a 14 2e 88 14 2b 88 04 2e 0f b6 0c 2e 0f b6 04 2b 03 c1 99 b9 ?? ?? ?? ?? f7 f9 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}