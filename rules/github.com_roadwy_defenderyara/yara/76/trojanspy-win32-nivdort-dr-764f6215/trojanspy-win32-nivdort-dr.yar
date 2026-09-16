rule TrojanSpy_Win32_Nivdort_DR{
	meta:
		description = "TrojanSpy:Win32/Nivdort.DR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 18 3b 44 24 1c 0f [0-20] 8b 44 24 14 0f b6 00 8b 4c 24 18 0f b6 11 31 c2 88 d3 88 19 } 		$a_01_1 = {c7 41 08 06 00 00 00 c7 41 04 01 00 00 00 c7 01 02 00 00 00 ff d0 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}