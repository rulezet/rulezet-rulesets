rule Worm_Win32_Dorkbot_I_4{
	meta:
		description = "Worm:Win32/Dorkbot.I,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 05 00 00 "
		
	strings :
		$a_00_0 = {23 72 6e 64 62 6f 74 } 		$a_00_1 = {23 72 6e 64 66 74 70 } 		$a_00_2 = {6e 67 72 2e 68 6f 73 74 6e 61 6d 65 } 		$a_00_3 = {5b 53 6c 6f 77 6c 6f 72 69 73 5d 3a } 		$a_01_4 = {76 4e 80 3e 53 75 18 80 7e 01 44 75 12 80 7e 02 47 75 0c 68 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*5) >=7
 
}