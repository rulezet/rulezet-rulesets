rule TrojanDropper_Win32_Sirefef_B_4{
	meta:
		description = "TrojanDropper:Win32/Sirefef.B,SIGNATURE_TYPE_ARHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 48 fc 83 c0 28 4a f3 a4 75 ea 33 c0 8d bd ?? ?? ?? ?? b9 ?? ?? ?? ?? f3 ab c7 85 ?? ?? ?? ?? 10 00 01 00 c7 } 	condition:
		((#a_03_0  & 1)*7) >=7
 
}