rule Trojan_Win32_Zbot_RB_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2d b2 6e 00 00 89 45 18 8b 4d f0 83 c1 08 2b 4d 14 89 4d ec c7 45 e4 c0 f1 0f 00 8b 55 ec 69 d2 7b 46 01 00 a1 ?? ?? ?? ?? 2b c2 89 45 ec } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}