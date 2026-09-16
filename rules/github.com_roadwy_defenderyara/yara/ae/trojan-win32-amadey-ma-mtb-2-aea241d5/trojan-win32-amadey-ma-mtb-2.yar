rule Trojan_Win32_Amadey_MA_MTB_2{
	meta:
		description = "Trojan:Win32/Amadey.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 3a 5c 4d 6b 74 6d 70 5c 41 6d 61 64 65 79 5c 52 65 6c 65 61 73 65 5c 41 6d 61 64 65 79 2e 70 64 62 } 		$a_03_1 = {6a 40 68 00 30 00 00 ff 77 50 50 ff b5 ?? ?? ?? ?? ff 15 } 		$a_03_2 = {8d 0c 33 03 4e 3c 6a 00 ff b1 ?? ?? ?? ?? 8b 81 ?? ?? ?? ?? 03 c6 50 8b 81 ?? ?? ?? ?? 03 85 ?? fe ff ff 50 ff b5 ?? fe ff ff ff 15 ?? ?? ?? ?? 8b 8d ?? fe ff ff 8d 5b 28 0f b7 47 06 41 89 8d ?? fe ff ff 3b c8 7e b8 } 	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=7
 
}