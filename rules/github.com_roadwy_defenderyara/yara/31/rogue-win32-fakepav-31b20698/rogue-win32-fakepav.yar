rule Rogue_Win32_FakePAV{
	meta:
		description = "Rogue:Win32/FakePAV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 64 6f 77 73 20 41 63 74 69 76 65 20 47 75 61 72 64 00 } 		$a_03_1 = {50 6a 00 6a 00 6a 20 6a 00 6a 00 6a 00 83 7d ?? 00 74 ?? 8b 55 ?? eb ?? ba ?? ?? ?? ?? 52 6a 00 ff 15 ?? ?? ?? ?? 85 c0 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}