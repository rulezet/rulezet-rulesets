rule TrojanSpy_Win32_Banker_AOT_3{
	meta:
		description = "TrojanSpy:Win32/Banker.AOT,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 69 74 65 6e 65 74 2e 73 65 72 61 73 61 2e 63 6f 6d 2e 62 72 } 		$a_01_1 = {63 6d 64 20 2f 6b 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 6a 61 76 61 5f 75 70 64 61 74 65 33 32 2e 63 6d 64 } 		$a_01_2 = {75 72 6c 32 3a } 		$a_01_3 = {77 69 6e 3a } 		$a_01_4 = {49 45 78 70 6c 6f 72 65 5f 45 78 70 6c 6f 72 65 72 5f 53 65 72 76 65 72 } 		$a_00_5 = {8b 55 f0 33 db 8a 5c 10 ff 33 5d e4 3b f3 7d 04 2b de eb 0c 3b f3 7c 08 81 c3 ff 00 00 00 2b de 8d 45 d4 8b d3 e8 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1) >=14
 
}