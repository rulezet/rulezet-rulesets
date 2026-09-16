rule Backdoor_Win32_Poison_E{
	meta:
		description = "Backdoor:Win32/Poison.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 e3 03 83 fb 00 75 03 83 ee 10 ad 33 07 ab 43 e2 ee } 		$a_01_1 = {8b 46 3c 8b 54 06 78 03 d6 8b 4a 18 8b 5a 20 03 de e3 35 49 8b 34 8b 03 75 08 33 ff 33 c0 fc ac 84 c0 74 07 c1 cf 0d 03 f8 eb f4 } 		$a_01_2 = {8b 75 08 81 e6 00 00 ff ff 66 ad 4e 4e 3d 4d 5a 00 00 74 08 81 ee 00 00 01 00 eb ed } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}