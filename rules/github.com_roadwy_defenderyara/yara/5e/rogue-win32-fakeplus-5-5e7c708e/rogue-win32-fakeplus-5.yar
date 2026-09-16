rule Rogue_Win32_FakePlus_5{
	meta:
		description = "Rogue:Win32/FakePlus,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff 35 44 21 41 00 56 ff 75 fc e8 53 bc ff ff 4f 75 ee 8b 4d fc 8d 81 b4 15 00 00 81 c1 64 31 00 00 33 08 6a 43 81 f1 87 d2 e3 f3 89 08 5f } 		$a_01_1 = {a3 34 1d 41 00 8b 45 0c ff 30 e8 28 0a 00 00 33 06 5f 35 d7 d5 e3 e3 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}