rule PWS_Win32_OnLineGames_BX_2{
	meta:
		description = "PWS:Win32/OnLineGames.BX,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 53 41 46 44 20 54 63 70 69 70 20 5b 54 43 50 2f 49 50 5d } 		$a_01_1 = {64 65 6c 2e 62 61 74 00 ff ff ff ff 07 00 00 00 3a 5f 64 65 6c 6d 65 } 		$a_01_2 = {ff ff ff 8b 55 fc 8b c3 b9 12 8d 40 00 e8 6d b2 ff ff 8b c3 8b d6 e8 b0 b4 ff ff 33 c0 5a 59 59 64 89 10 68 03 8d 40 00 8d 45 fc e8 8f af ff ff c3 e9 b1 a9 ff ff eb f0 5e 5b 59 5d c3 00 00 ff ff ff ff 06 00 00 00 72 6f 2e 64 6c 6c 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}