rule Rogue_Win32_Fakeinit{
	meta:
		description = "Rogue:Win32/Fakeinit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 c3 22 00 00 00 55 8b d2 33 ce 47 fc 5d 50 8b c2 58 8d 2d ?? ?? ?? ?? 81 d5 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 33 d4 d6 d6 81 fb ?? ?? ?? ?? 75 d0 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}