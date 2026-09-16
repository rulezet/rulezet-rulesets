rule TrojanSpy_Win32_Ursnif_IC_bit{
	meta:
		description = "TrojanSpy:Win32/Ursnif.IC!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c 6d 73 6c 30 } 		$a_01_1 = {0f b7 0b c1 e9 0c 83 f9 03 74 17 83 f9 0a 75 27 0f b7 0b 81 e1 ff 0f 00 00 03 ce 01 01 11 51 04 } 		$a_01_2 = {0f ba 26 1d 73 13 0f ba 26 1f 0f 92 c2 f6 da 1b d2 83 e2 20 83 c2 20 eb 1b 0f ba 26 1e 73 12 0f ba 26 1f 0f 92 c2 f6 da 1b d2 83 e2 02 42 42 eb 03 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}