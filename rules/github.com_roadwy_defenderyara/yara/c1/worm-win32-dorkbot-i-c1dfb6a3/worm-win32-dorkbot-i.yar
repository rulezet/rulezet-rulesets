rule Worm_Win32_Dorkbot_I{
	meta:
		description = "Worm:Win32/Dorkbot.I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {4d 6f 64 75 6c 65 33 00 50 72 6f 79 65 63 74 6f 31 00 } 		$a_01_1 = {c7 85 a0 fd ff ff 83 00 00 00 c7 85 98 fd ff ff 02 00 00 00 8d 95 98 fd ff ff 8b 45 d8 6a 23 59 2b 48 14 c1 e1 04 8b 45 d8 8b 40 0c 03 c8 e9 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}