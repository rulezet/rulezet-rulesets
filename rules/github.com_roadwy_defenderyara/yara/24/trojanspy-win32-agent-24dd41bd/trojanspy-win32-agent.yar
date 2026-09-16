rule TrojanSpy_Win32_Agent{
	meta:
		description = "TrojanSpy:Win32/Agent,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_00_0 = {e8 00 00 00 00 5f 33 f7 b8 a1 9f 40 00 8b c8 51 83 c0 32 c3 bb 00 10 40 00 81 eb 28 71 ff ff 53 75 05 33 c0 74 01 e9 fc b8 4b 9f } 		$a_02_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 7e 54 65 6d 70 [0-04] 2e 74 6d 70 00 00 00 00 00 00 00 00 00 00 00 00 } 		$a_00_2 = {63 3a 5c 68 6f 6d 65 5c 6d 77 74 65 73 74 5c 74 6d 70 5c 77 2e 65 78 65 } 		$a_00_3 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 31 2e 65 78 65 } 	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=11
 
}