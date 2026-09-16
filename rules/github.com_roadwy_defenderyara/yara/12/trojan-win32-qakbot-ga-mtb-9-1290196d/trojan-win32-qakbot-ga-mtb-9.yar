rule Trojan_Win32_Qakbot_GA_MTB_9{
	meta:
		description = "Trojan:Win32/Qakbot.GA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 3a 5c 6d 64 2d 70 72 6f 6a 5c 70 72 64 79 6a 66 5c 72 74 63 33 32 2e 70 64 62 } 		$a_01_1 = {d0 2d 6b 65 1c c0 d3 0b bd fd 13 89 21 41 72 eb 22 e1 79 03 b7 6d 0c 64 76 f4 3d c0 55 44 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}