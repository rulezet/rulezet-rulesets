rule TrojanSpy_Win32_Gamker_A{
	meta:
		description = "TrojanSpy:Win32/Gamker.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {6f 6c 6c 79 64 62 67 2e 65 78 65 } 		$a_01_1 = {3a 5a 6f 6e 65 2e 49 64 65 6e 74 69 66 69 65 72 } 		$a_01_2 = {88 1f 8b 7d ec 88 5d ff 0f b6 5d 0b 88 1f 0f b6 5d 0b 0f b6 7d ff 03 fb 8a 5d fe 81 e7 ff 00 00 00 32 1c 07 fe c1 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10) >=12
 
}