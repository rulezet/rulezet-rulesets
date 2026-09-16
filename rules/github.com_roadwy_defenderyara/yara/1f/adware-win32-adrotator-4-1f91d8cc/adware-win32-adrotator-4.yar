rule Adware_Win32_AdRotator_4{
	meta:
		description = "Adware:Win32/AdRotator,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 83 4d fc ff a3 ?? ?? ?? ?? 8b 30 57 ff 15 ?? ?? ?? ?? ff 75 0c ff 75 08 56 50 ff 15 ?? ?? ?? ?? ff d0 } 		$a_03_1 = {0f b6 55 0b 33 d0 8b 46 08 2b c1 88 55 0b 8a 55 0b 83 c0 0b 32 10 8b 06 88 14 01 41 83 f9 0b 72 ?? ff 76 08 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}