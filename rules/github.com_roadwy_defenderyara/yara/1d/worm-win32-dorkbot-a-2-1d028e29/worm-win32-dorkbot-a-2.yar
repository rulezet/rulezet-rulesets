rule Worm_Win32_Dorkbot_A_2{
	meta:
		description = "Worm:Win32/Dorkbot.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 00 00 00 00 38 00 16 00 01 00 43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 44 00 6e 00 4b 00 41 00 73 00 65 00 65 00 59 00 4f 00 55 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}