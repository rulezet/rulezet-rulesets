rule Worm_Win32_Dorkbot_A{
	meta:
		description = "Worm:Win32/Dorkbot.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {52 50 68 d0 37 10 f2 68 50 40 40 00 56 ff 51 20 85 c0 } 		$a_01_1 = {6e 00 41 00 6e 00 64 00 72 00 20 00 68 00 75 00 74 00 74 00 61 00 50 00 2e 00 76 00 62 00 70 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}