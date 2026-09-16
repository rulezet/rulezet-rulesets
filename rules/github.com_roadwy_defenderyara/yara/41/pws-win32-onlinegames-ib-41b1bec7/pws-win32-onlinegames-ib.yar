rule PWS_Win32_OnLineGames_IB{
	meta:
		description = "PWS:Win32/OnLineGames.IB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 4e 46 2e 65 78 65 } 		$a_01_1 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 } 		$a_01_2 = {8b 44 24 08 8a da 03 c2 f6 d3 32 18 32 d9 42 3b 54 24 0c 88 18 7c e9 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3) >=4
 
}