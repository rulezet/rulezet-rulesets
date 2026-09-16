rule PWS_Win32_OnLineGames_ZFM_3{
	meta:
		description = "PWS:Win32/OnLineGames.ZFM,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 64 61 74 61 2e 65 76 70 } 		$a_01_1 = {33 36 30 74 72 61 79 2e 65 78 65 } 		$a_01_2 = {5c 64 6c 6c 63 61 63 68 65 5c 6c 70 6b 2e 64 6c 6c } 		$a_01_3 = {64 65 6c 20 22 25 73 22 20 69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 64 65 6c 65 74 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}