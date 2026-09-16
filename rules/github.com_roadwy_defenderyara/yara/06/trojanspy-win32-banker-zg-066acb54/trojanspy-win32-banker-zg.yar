rule TrojanSpy_Win32_Banker_ZG{
	meta:
		description = "TrojanSpy:Win32/Banker.ZG,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b7 5c 78 fe 33 5d e4 3b 5d e8 7f 0b 81 c3 ff 00 00 00 2b 5d e8 eb 03 2b 5d e8 } 		$a_01_1 = {5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 69 00 6e 00 6e 00 69 00 6d 00 61 00 74 00 65 00 73 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}