rule TrojanSpy_Win32_Banker_ABG{
	meta:
		description = "TrojanSpy:Win32/Banker.ABG,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {ba 03 00 00 00 e8 ?? ?? ?? ?? 8b 85 ?? ff ff ff e8 ?? ?? ?? ?? 50 6a 00 e8 ?? ?? ?? ?? 8b ?? 6a 01 } 		$a_03_1 = {eb 07 b2 02 e8 ?? ?? ff ff 8b 45 fc 80 78 5b 00 74 ?? 8b 45 fc 8b 40 44 80 b8 ?? ?? 00 00 01 ?? ?? 8b ?? fc } 		$a_00_2 = {0e 54 4b 65 79 50 72 65 73 73 45 76 65 6e 74 } 		$a_00_3 = {53 69 6c 65 6e 74 } 		$a_00_4 = {70 61 73 73 77 6f 72 64 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}