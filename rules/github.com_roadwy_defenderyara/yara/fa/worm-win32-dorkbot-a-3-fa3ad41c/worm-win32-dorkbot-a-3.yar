rule Worm_Win32_Dorkbot_A_3{
	meta:
		description = "Worm:Win32/Dorkbot.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 74 61 72 74 20 25 25 63 64 25 25 52 45 43 59 43 4c 45 52 5c 25 73 } 		$a_00_1 = {6e 67 72 42 6f 74 } 		$a_03_2 = {83 c4 0c 53 8d 45 f8 50 68 00 04 00 00 8d 8d ?? ?? ff ff 51 6a 0c 8d 55 ?? 52 68 00 14 2d 00 56 c7 85 ?? ?? ff ff 00 04 00 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}