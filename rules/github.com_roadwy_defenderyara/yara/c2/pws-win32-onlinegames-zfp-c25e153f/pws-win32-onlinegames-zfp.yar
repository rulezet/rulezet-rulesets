rule PWS_Win32_OnLineGames_ZFP{
	meta:
		description = "PWS:Win32/OnLineGames.ZFP,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_03_0 = {c6 45 f8 50 c6 45 f9 4f [0-10] c6 45 fa 53 c6 45 fb 54 } 		$a_01_1 = {69 c6 45 f6 62 c6 45 f7 61 c6 45 f8 6f c6 45 f9 2e c6 45 fa 61 c6 45 fb 73 c6 45 fc 70 } 		$a_00_2 = {25 73 5f 25 64 25 73 00 2e 6a 70 67 } 		$a_00_3 = {44 4e 46 2e 65 78 65 } 		$a_00_4 = {51 51 4c 6f 67 69 6e 2e 65 78 65 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=22
 
}