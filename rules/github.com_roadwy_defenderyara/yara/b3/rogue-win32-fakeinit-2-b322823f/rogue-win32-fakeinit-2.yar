rule Rogue_Win32_Fakeinit_2{
	meta:
		description = "Rogue:Win32/Fakeinit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 eb 2f 00 00 00 f7 d9 87 d6 84 c9 68 ce 5c 3a 01 41 5d 33 c6 81 fb e9 37 02 00 75 e3 } 		$a_01_1 = {81 e9 25 00 00 00 33 e9 ff f6 81 f8 ab fe 13 00 5b f7 d2 d6 81 f9 fc 61 c9 c3 75 e4 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}