rule Trojan_Win32_Toga_rfn{
	meta:
		description = "Trojan:Win32/Toga!rfn,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 45 f0 8b 45 fc 8b 40 28 03 45 f4 8b 55 f0 89 42 04 8b 45 f0 8b 55 f4 89 10 8b 45 fc 05 a0 00 00 00 8b 10 85 d2 74 0c } 		$a_03_1 = {8b 45 fc 83 c0 78 8b 10 85 d2 74 18 03 55 f4 8b 4d f0 89 91 ?? ?? ?? ?? 8b 40 04 8b 55 f0 89 82 ?? ?? ?? ?? 8b 45 fc } 		$a_01_2 = {6a 00 6a 01 8b 45 f4 50 8b 45 f0 ff 50 04 85 c0 75 0a 8b 45 f0 33 d2 89 50 04 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}