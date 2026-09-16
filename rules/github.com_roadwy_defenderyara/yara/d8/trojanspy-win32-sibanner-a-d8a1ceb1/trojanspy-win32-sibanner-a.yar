rule TrojanSpy_Win32_Sibanner_A{
	meta:
		description = "TrojanSpy:Win32/Sibanner.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 55 08 03 55 f4 8b 45 f8 8a 0a 32 4c 05 fc 8b 55 08 03 55 f4 88 0a } 		$a_01_1 = {8b 55 f8 33 c0 8a 44 15 fc d1 f8 8b 4d f8 88 44 0d fc 8b 55 f8 8a 44 15 fc 0c 80 8b 4d f8 88 44 0d fc } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}