rule PWS_Win32_OnLineGames_ZFM_2{
	meta:
		description = "PWS:Win32/OnLineGames.ZFM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b 4f 3c 83 c4 0c 03 cf 66 81 79 18 0b 01 75 ?? 66 8b 51 58 66 3b c2 1b db f7 db 03 da 66 8b 51 5a } 		$a_00_1 = {00 6b 73 75 73 65 72 2e 64 6c 6c 00 00 6d 69 64 69 6d 61 70 2e 64 6c 6c 00 63 6f 6d 72 65 73 2e 64 6c 6c 00 } 		$a_00_2 = {73 73 65 72 64 64 41 63 6f 72 50 74 65 47 } 		$a_00_3 = {25 73 2c 20 53 65 72 76 65 72 4d 61 69 6e 20 25 63 25 73 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}