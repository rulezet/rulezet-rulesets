rule Adware_Win32_AdRotator_13{
	meta:
		description = "Adware:Win32/AdRotator,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 8b 34 01 66 33 70 fe 66 89 30 83 c0 02 4a 75 ef } 		$a_01_1 = {74 15 89 7d 0c 66 8b 38 66 33 3c 02 ff 4d 0c 8b 19 66 89 3c 1e 75 ee } 		$a_01_2 = {0f b6 54 10 03 8d 4c 01 02 8b 0e 30 54 01 03 8b 56 04 0f b6 54 10 04 8d 4c 01 03 } 		$a_00_3 = {c6 45 fc 06 8b 45 f0 89 07 89 75 f0 c6 45 fc 05 c7 45 ec 01 00 00 00 c6 45 fc 02 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}