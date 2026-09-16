rule Trojan_Win32_Trickbot_B_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 7d f0 83 ef 01 89 45 ec 8b 45 f0 0f af c7 83 e0 01 83 f8 00 0f 94 c0 83 fb 0a 0f 9c c4 08 e0 a8 01 } 		$a_01_1 = {0f b6 f0 8a 44 24 1e 0f b6 f8 89 f8 31 f0 88 44 24 1e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}