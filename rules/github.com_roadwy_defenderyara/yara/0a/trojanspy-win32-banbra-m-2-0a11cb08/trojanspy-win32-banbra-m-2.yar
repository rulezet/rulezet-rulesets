rule TrojanSpy_Win32_Banbra_M_2{
	meta:
		description = "TrojanSpy:Win32/Banbra.M,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 6a 73 6e 00 00 00 00 67 7c 67 78 6c 69 7a 72 39 32 26 6e 6e 66 00 00 } 		$a_03_1 = {8a 55 fb 8a 14 17 80 e2 0a 32 c2 33 d2 8a d3 8a 14 16 80 e2 f0 80 e2 f0 02 d0 33 c0 8a c3 8b 4d fc 88 14 01 fe 45 fb [0-10] 33 d2 8a 55 fb 3b c2 ?? 04 c6 45 fb 00 43 fe 4d fa 75 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}