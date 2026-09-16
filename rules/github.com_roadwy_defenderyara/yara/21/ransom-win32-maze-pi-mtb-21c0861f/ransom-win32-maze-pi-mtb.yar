rule Ransom_Win32_Maze_PI_MTB{
	meta:
		description = "Ransom:Win32/Maze.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4d b8 83 c1 01 89 4d b8 8b 55 b8 3b 55 18 73 [0-04] 8b 45 ?? 03 45 b8 0f b6 08 8b 55 b8 0f b6 44 15 bc 33 c8 8b 55 14 03 55 b8 88 0a eb } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}