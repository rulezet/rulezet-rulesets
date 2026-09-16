rule Rogue_Win32_Winwebsec{
	meta:
		description = "Rogue:Win32/Winwebsec,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f 31 52 81 c2 da d4 a6 67 ba 5a 68 eb cf 8d 1d ?? ?? ?? ?? 58 f7 d6 c1 ef 07 90 13 8d 1d ?? ?? ?? ?? bf 5f 9b b8 e3 8d 0d ?? ?? ?? ?? 83 f8 0a 0f 82 ?? ?? ?? ?? e9 d3 00 00 00 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}