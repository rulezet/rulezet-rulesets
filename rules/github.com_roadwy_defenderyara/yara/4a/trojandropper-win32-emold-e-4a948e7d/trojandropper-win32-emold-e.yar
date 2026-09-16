rule TrojanDropper_Win32_Emold_E{
	meta:
		description = "TrojanDropper:Win32/Emold.E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 31 0b c0 74 ?? 33 c0 64 8b 40 30 83 b8 b0 00 00 00 02 [0-06] 50 58 8b e4 6a 00 68 51 4f 68 57 54 90 13 b8 ?? ?? ?? ?? 81 c0 ?? ?? ?? ?? ff 55 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}