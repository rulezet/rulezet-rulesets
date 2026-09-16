rule Adware_Win32_AdRotator_5{
	meta:
		description = "Adware:Win32/AdRotator,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 4d ec e8 ?? ?? ?? ?? 8b f8 8d 4d ec 81 e7 f0 00 00 00 e8 ?? ?? ?? ?? 83 e0 0f 0b c7 04 ?? 88 45 f3 8d 45 f3 50 8b c6 e8 ?? ?? ?? ?? 8b 45 ec 80 38 00 75 cb } 		$a_01_1 = {2d 30 30 30 30 2d 30 30 30 30 30 30 30 30 30 30 31 32 46 38 36 38 7d 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}