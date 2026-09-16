rule Rogue_Win32_FakePAV_2{
	meta:
		description = "Rogue:Win32/FakePAV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {54 00 68 00 69 00 6e 00 6b 00 50 00 6f 00 69 00 6e 00 74 00 2e 00 6c 00 6e 00 6b 00 00 00 } 		$a_03_1 = {8b 55 f8 8b c3 8b 08 ff 51 38 8d 45 f0 e8 ?? ?? ?? ?? ff 75 f0 68 ?? ?? ?? 00 ff 75 fc 8d 45 f4 ba 03 00 00 00 e8 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}