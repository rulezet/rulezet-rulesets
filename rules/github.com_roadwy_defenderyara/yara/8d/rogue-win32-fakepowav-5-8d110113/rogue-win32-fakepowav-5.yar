rule Rogue_Win32_FakePowav_5{
	meta:
		description = "Rogue:Win32/FakePowav,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 70 79 20 50 72 6f 74 65 63 74 6f 72 00 } 		$a_01_1 = {6c 73 61 73 63 73 2e 65 78 65 00 } 		$a_03_2 = {8b f0 6a 00 6a 1a 56 6a 00 e8 ?? ?? ff ff 8d 45 f8 8b d6 e8 ?? ?? fe ff 8b 45 f8 8d 55 fc e8 ?? ?? fe ff 8b 55 fc 8b c3 b9 ?? ?? ?? ?? e8 ?? ?? fe ff 8b c3 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=4
 
}