rule Backdoor_Win32_Plugx_K_dha_2{
	meta:
		description = "Backdoor:Win32/Plugx.K!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {43 61 6e 27 74 20 66 69 6e 64 20 46 75 6e 63 20 30 78 25 78 20 69 6e 20 25 73 21 } 		$a_01_1 = {00 53 76 63 4d 61 69 6e 00 } 		$a_03_2 = {68 8b c4 5d 63 56 a3 ?? ?? ?? ?? e8 ?? ?? ff ff 68 b2 bb 55 3a 56 a3 ?? ?? ?? ?? e8 ?? ?? ff ff 68 5a 6e db db 56 a3 ?? ?? ?? ?? e8 ?? ?? ff ff } 		$a_03_3 = {8a 4f 01 47 84 c9 75 f8 8b c8 c1 e9 02 8b f2 f3 a5 8b c8 83 e1 03 8d 85 ?? ?? ?? ?? f3 a4 8d 48 01 8a 10 40 84 d2 75 ?? 2b c1 80 ?? ?? ?? ?? ?? ff 5c } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}