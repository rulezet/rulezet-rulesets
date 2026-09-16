rule Adware_Win32_AdRotator_19{
	meta:
		description = "Adware:Win32/AdRotator,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {c6 45 fc 07 8b 45 f0 89 (06|07) 89 90 03 01 01 5d 75 f0 c6 45 fc 06 c7 45 e8 01 00 00 00 c6 45 fc 02 } 		$a_01_1 = {c6 45 fc 07 8b 45 ec 89 06 89 7d ec c6 45 fc 06 c7 45 e4 01 00 00 00 c6 45 fc 02 } 		$a_01_2 = {89 55 08 83 65 fc 00 8b 4d 0c 8b 39 89 3a 83 21 00 83 4d fc ff } 		$a_03_3 = {66 33 3c 02 ff (4d|6d) 0c 8b 19 66 89 3c 1e 75 ee 66 8b 3c 02 66 33 38 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}