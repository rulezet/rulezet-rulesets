rule Rogue_Win32_Defmid{
	meta:
		description = "Rogue:Win32/Defmid,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {32 c0 5e c2 04 00 8b 4e 0c 6a 00 6a 00 6a 00 6a 02 6a 00 51 ff 15 ?? ?? ?? ?? 85 c0 89 46 10 75 06 32 c0 5e c2 04 00 6a 00 6a 00 6a 00 6a 04 50 ff 15 ?? ?? ?? ?? 89 06 b0 01 5e c2 04 00 } 		$a_00_1 = {42 42 30 32 42 37 45 45 2d 35 46 43 32 2d 34 30 37 64 2d 41 36 45 43 2d 35 44 42 32 34 43 30 46 41 37 43 33 } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}