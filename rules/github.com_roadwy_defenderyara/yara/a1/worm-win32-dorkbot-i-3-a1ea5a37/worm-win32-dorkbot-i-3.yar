rule Worm_Win32_Dorkbot_I_3{
	meta:
		description = "Worm:Win32/Dorkbot.I,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {25 73 5c 70 72 6f 67 72 61 6d 64 61 74 61 } 		$a_00_1 = {25 73 5c 52 65 63 79 63 6c 65 72 } 		$a_00_2 = {25 73 5c 2a 2e 2a } 		$a_00_3 = {5c 55 70 64 61 74 65 5c } 		$a_01_4 = {6a 00 6a 02 8b f8 c7 44 24 20 28 01 00 00 ff 15 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}