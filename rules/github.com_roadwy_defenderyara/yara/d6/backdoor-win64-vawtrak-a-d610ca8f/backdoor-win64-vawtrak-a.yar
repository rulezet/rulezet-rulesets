rule Backdoor_Win64_Vawtrak_A{
	meta:
		description = "Backdoor:Win64/Vawtrak.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {5b 56 4e 43 5d 20 53 74 61 72 74 20 53 65 76 65 72 } 		$a_00_1 = {74 68 69 73 2e 47 65 74 58 48 52 3d 66 75 6e 63 74 69 6f 6e 28 29 7b 22 75 6e 64 65 66 69 6e 65 64 22 } 		$a_02_2 = {48 83 c1 08 e8 ?? ?? ?? ?? f7 d8 1b c9 f7 d9 81 c1 fe 00 00 00 89 4b 04 eb ?? c7 41 04 ff 00 00 00 48 83 c1 08 ba 05 00 00 00 ff 15 ?? ?? ?? ?? eb ?? c7 41 04 ff 00 00 00 } 		$a_02_3 = {c1 c8 03 69 c0 fd 43 03 00 41 bf c3 9e 26 00 be 00 00 ff 7f 41 03 c7 44 8b e0 89 ?? ?? ?? ?? ?? 44 23 e6 85 c0 75 ?? ff 15 ?? ?? ?? ?? c1 c8 03 69 c0 fd 43 03 00 41 bd ff 7f 00 00 41 03 c7 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}