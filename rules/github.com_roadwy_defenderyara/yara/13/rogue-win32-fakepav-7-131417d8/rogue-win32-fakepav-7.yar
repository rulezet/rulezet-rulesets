rule Rogue_Win32_FakePAV_7{
	meta:
		description = "Rogue:Win32/FakePAV,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 03 00 00 "
		
	strings :
		$a_81_0 = {2f 7a 7a 2e 70 68 70 3f 00 } 		$a_03_1 = {43 66 83 fb 5b [0-03] 0f 85 ?? ?? ?? ?? 8b 06 8b 80 ac 03 00 00 b2 01 8b 08 ff 51 64 8b 06 8b 80 ?? ?? 00 00 b2 01 8b 08 ff 51 64 68 ?? ?? ?? 00 ff 75 f4 68 ?? ?? ?? 00 ff 75 ec 68 ?? ?? ?? 00 68 ?? ?? ?? 00 } 		$a_02_2 = {6a 00 6a 00 8d 45 fc e8 ?? ?? ?? ?? 8d 45 fc 50 8d 4d f8 ba 03 00 00 00 b8 a8 1d 4c 00 e8 ?? ?? ?? ?? 8b 55 f8 58 e8 ?? ?? ?? ?? 8b 45 fc 50 a1 44 13 4d 00 50 6a 00 e8 } 	condition:
		((#a_81_0  & 1)*2+(#a_03_1  & 1)*2+(#a_02_2  & 1)*2) >=4
 
}