rule Trojan_Win32_Trickbot_EM_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.EM!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ba 08 00 00 00 6b c2 00 8b 4d fc 8b 55 f4 8b 49 24 2b 0c 02 03 4d fc 89 4d d8 ba 08 00 00 00 6b c2 00 8b 4d fc 8b 55 f4 8b 49 1c 2b 0c 02 03 4d fc 89 4d d4 ba 08 00 00 00 6b c2 00 8b 4d fc 8b 55 f4 8b 49 20 2b 0c 02 03 4d fc 89 4d e0 c7 45 ec 00 00 00 00 8b 55 fc 8b 42 18 89 45 f0 8b 4d f0 d1 e9 89 4d f8 8b 55 f0 83 c2 01 89 55 e8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}