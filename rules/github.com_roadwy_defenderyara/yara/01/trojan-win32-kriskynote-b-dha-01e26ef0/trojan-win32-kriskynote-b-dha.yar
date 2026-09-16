rule Trojan_Win32_Kriskynote_B_dha{
	meta:
		description = "Trojan:Win32/Kriskynote.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 69 6e 67 4f 66 50 68 61 6e 74 6f 6d 30 33 30 38 5f 32 30 31 34 30 38 32 36 } 		$a_01_1 = {56 56 ff 74 24 14 89 44 24 1c 50 57 ff d3 50 57 56 56 ff d5 8b 44 24 10 5e } 		$a_01_2 = {57 48 83 ec 40 b8 01 00 00 00 3b d0 0f 85 fd 00 00 00 ff 15 3e 10 00 00 85 c0 0f 84 e3 00 00 00 83 64 24 58 00 ff 15 d3 0f 00 00 48 8d 54 24 58 48 8b c8 ff 15 15 10 00 00 b9 02 00 00 00 39 4c 24 58 48 8b f0 0f 8c b8 00 00 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}