rule Trojan_Win32_Chksyn_gen_A{
	meta:
		description = "Trojan:Win32/Chksyn.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_00_0 = {c7 45 e8 00 00 00 00 83 7d e4 00 75 0a b8 0f 00 00 c0 e9 91 00 00 00 83 7d ec 00 75 10 8b 55 e4 83 c2 64 } 		$a_02_1 = {50 8b 4d f0 83 c1 04 51 e8 ?? 23 00 00 83 c4 08 85 c0 74 07 c7 45 f4 34 00 00 c0 68 ?? ?? ?? ?? 6a 00 } 		$a_03_2 = {74 4e 68 00 01 00 00 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? b8 ?? ?? ?? ?? 99 52 50 68 76 01 00 00 e8 ?? ?? ff ff 85 c0 74 17 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}