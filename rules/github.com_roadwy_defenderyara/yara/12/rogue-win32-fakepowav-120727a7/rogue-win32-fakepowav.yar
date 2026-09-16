rule Rogue_Win32_FakePowav{
	meta:
		description = "Rogue:Win32/FakePowav,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 5a 59 59 64 89 10 68 ?? ?? ?? ?? 8d 45 ?? ba ?? 00 00 00 e8 ?? ?? ?? ?? c3 e9 ?? ?? ?? ?? eb eb 5b e8 [0-20] 55 6e 69 6e 73 74 61 6c 6c 00 } 		$a_00_1 = {48 6f 77 54 6f 42 75 79 2e 74 78 74 } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}