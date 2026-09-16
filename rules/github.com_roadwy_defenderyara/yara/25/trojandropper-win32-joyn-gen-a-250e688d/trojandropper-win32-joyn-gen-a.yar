rule TrojanDropper_Win32_Joyn_gen_A{
	meta:
		description = "TrojanDropper:Win32/Joyn.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {6a 00 68 80 00 00 00 6a 30 6a 30 6a 02 68 00 00 00 40 68 ?? ?? ?? ?? e8 } 		$a_02_1 = {68 04 01 00 00 e8 ?? ?? ?? ?? 6a 01 68 ?? ?? ?? ?? 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a ?? e8 ?? ?? ?? ?? b8 01 00 00 00 c9 c2 10 00 } 		$a_03_2 = {4e 00 4a 00 4f 00 59 00 [0-30] 2e 00 4a 00 50 00 47 00 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}