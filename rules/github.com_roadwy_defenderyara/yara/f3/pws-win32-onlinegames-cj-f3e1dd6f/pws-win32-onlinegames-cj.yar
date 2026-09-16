rule PWS_Win32_OnLineGames_CJ{
	meta:
		description = "PWS:Win32/OnLineGames.CJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c1 e9 08 32 d1 88 54 38 ff 8b 04 24 0f b6 44 38 ff 66 03 f0 66 69 c6 6d ce 66 05 bf 58 } 		$a_01_1 = {73 74 61 72 74 20 57 6d 64 6d 50 6d 53 4e 00 } 		$a_01_2 = {73 74 6f 70 20 57 6d 64 6d 50 6d 53 4e 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}