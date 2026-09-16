rule Trojan_Win32_Donbot_A{
	meta:
		description = "Trojan:Win32/Donbot.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {65 6d 61 69 6c 3d 25 73 } 		$a_00_1 = {50 4f 53 54 20 2f 67 61 74 65 77 61 79 2f 69 6e 64 65 78 20 48 54 54 50 2f 31 2e 30 } 		$a_03_2 = {8b 44 24 10 30 0c 06 57 43 e8 ?? ?? ?? ?? 59 3b d8 72 e7 8b 44 24 10 f6 14 06 50 46 e8 ?? ?? ?? ?? 59 3b f0 72 c7 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}