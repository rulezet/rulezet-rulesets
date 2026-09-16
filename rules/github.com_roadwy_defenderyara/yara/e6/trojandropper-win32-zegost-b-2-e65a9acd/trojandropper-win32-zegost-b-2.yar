rule TrojanDropper_Win32_Zegost_B_2{
	meta:
		description = "TrojanDropper:Win32/Zegost.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {e8 00 00 00 00 5d 81 ed ?? ?? ?? ?? bb ?? ?? ?? ?? 03 dd b9 ?? ?? ?? ?? ?? 80 33 [0-01] 43 e2 } 		$a_01_1 = {6a 65 68 6d 54 69 6d 68 79 73 74 65 68 47 65 74 53 } 		$a_03_2 = {83 c4 0c c6 45 ?? 47 c6 45 ?? 6f c6 45 ?? 62 c6 45 ?? 61 c6 45 ?? 5c c6 45 ?? 6b c6 45 ?? 69 } 		$a_00_3 = {6b 2d 20 65 78 65 2e 74 73 6f 68 } 		$a_00_4 = {69 6b 5c 6c 61 62 6f 6c 47 73 25 73 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}