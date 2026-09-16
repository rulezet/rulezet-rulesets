rule PWS_Win32_Zbot_GOY_bit{
	meta:
		description = "PWS:Win32/Zbot.GOY!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 1f 33 c1 c1 e9 08 0f b6 c0 33 0c 85 ?? ?? ?? ?? 47 3b fa 72 e8 } 		$a_03_1 = {6a 20 5a 8d 4c 24 ?? e8 ?? ?? ?? ?? 31 44 34 ?? 83 c6 04 3b f2 72 e9 } 		$a_03_2 = {8b c1 83 e0 03 8a 44 04 ?? 30 44 0c ?? 41 83 f9 08 72 ed } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}