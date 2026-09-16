rule Trojan_Win32_Pikabot_PA_MTB_2{
	meta:
		description = "Trojan:Win32/Pikabot.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 44 0d b4 34 [0-02] 88 44 0d e4 41 83 f9 19 7c f0 } 		$a_03_1 = {4a 70 55 71 [0-08] c7 45 ?? 61 76 7d 4d c7 45 ?? 6a 62 6b 76 c7 45 ?? 69 65 70 6d c7 45 ?? 6b 6a 54 76 c7 45 ?? 6b 67 61 77 [0-08] [0-08] 34 } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}