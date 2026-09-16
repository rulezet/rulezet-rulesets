rule Trojan_Win32_Zbot_AZB_MTB_4{
	meta:
		description = "Trojan:Win32/Zbot.AZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 45 0f fe c6 45 12 ac c6 45 9d 92 c6 45 0d b8 c6 45 b8 ea c6 45 3e 3e c6 45 76 8f c6 45 fc bf c6 45 65 b0 c6 45 cd 24 c6 45 58 24 c6 45 94 d4 c6 45 f5 f8 c6 45 dc 51 c6 45 a8 fa c6 45 d4 fb c6 45 3b 30 c6 45 81 55 c6 45 bc f8 c6 45 57 03 c6 45 fb f0 c6 45 2a c5 c6 45 ad 4a c6 45 33 cb c6 45 93 28 c6 45 8e f0 c6 45 39 b9 c6 45 f7 e9 c6 45 18 1f c6 45 2b e1 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}