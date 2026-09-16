rule Worm_Win32_Conficker_E{
	meta:
		description = "Worm:Win32/Conficker.E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {50 68 02 02 00 00 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 6a 1e 99 59 f7 f9 83 c2 05 69 d2 60 ea 00 00 52 ff d7 6a 63 e8 90 16 55 8b ec 6a ff } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}