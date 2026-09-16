rule TrojanSpy_Win32_Banker_AOP{
	meta:
		description = "TrojanSpy:Win32/Banker.AOP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 00 44 00 4b 00 55 00 50 00 44 00 54 00 3d 00 } 		$a_03_1 = {2e 00 63 00 70 00 6c 00 [0-16] 63 00 6d 00 64 00 20 00 2f 00 63 00 } 		$a_03_2 = {83 fb 01 75 0d 8d 55 fc b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 fb 02 75 0d 8d 55 fc b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 fb 03 75 0d 8d 55 fc b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 c0 55 } 		$a_01_3 = {74 05 83 e8 04 8b 00 89 45 ec 33 f6 8d 45 dc 50 b9 02 00 00 00 ba 01 00 00 00 8b 45 fc } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}