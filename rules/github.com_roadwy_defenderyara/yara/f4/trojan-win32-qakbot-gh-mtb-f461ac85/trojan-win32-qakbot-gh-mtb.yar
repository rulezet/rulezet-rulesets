rule Trojan_Win32_Qakbot_GH_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 e6 00 09 d6 8b 55 ?? 89 75 ?? 2b 75 ?? 0b b3 ?? ?? ?? ?? 83 e1 00 31 f1 8b 75 ?? fc f3 a4 90 0a 2d 00 89 55 [0-04] 33 93 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}