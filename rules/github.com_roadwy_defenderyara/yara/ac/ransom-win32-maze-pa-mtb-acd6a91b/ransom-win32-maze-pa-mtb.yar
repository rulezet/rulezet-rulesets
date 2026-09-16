rule Ransom_Win32_Maze_PA_MTB{
	meta:
		description = "Ransom:Win32/Maze.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 4d f8 83 c1 01 89 4d f8 8b 55 f8 3b 55 ?? 73 ?? 8b 45 10 03 45 f8 0f b6 08 8b 55 f8 0f b6 44 15 ?? 33 c8 8b 55 ?? 03 55 f8 88 0a eb } 		$a_00_1 = {8b 55 f4 33 55 f0 03 55 ec 8b 45 fc 8b 4d 08 03 14 81 8b 45 fc 8b 4d 08 89 14 81 } 	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1) >=11
 
}