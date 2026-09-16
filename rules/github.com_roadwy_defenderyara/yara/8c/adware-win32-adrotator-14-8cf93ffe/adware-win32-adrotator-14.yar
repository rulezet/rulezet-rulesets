rule Adware_Win32_AdRotator_14{
	meta:
		description = "Adware:Win32/AdRotator,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8d 4d ec e8 ?? ?? ?? ?? 8b f8 8d 4d ec 81 e7 f0 00 00 00 e8 ?? ?? ?? ?? 83 e0 0f 0b c7 04 ?? 88 45 f3 56 8d 45 f3 50 8b 45 e8 e8 ?? ?? ?? ?? 8b 45 ec 80 38 00 75 c9 } 		$a_01_1 = {4e 53 5f 46 72 65 65 00 78 70 63 6f 6d 2e 64 6c 6c 00 } 		$a_01_2 = {50 52 5f 41 74 6f 6d 69 63 44 65 63 72 65 6d 65 6e 74 00 00 6e 73 70 72 34 2e 64 6c 6c 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}