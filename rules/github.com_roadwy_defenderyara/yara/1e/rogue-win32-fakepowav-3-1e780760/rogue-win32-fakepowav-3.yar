rule Rogue_Win32_FakePowav_3{
	meta:
		description = "Rogue:Win32/FakePowav,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 ff ff ff 00 52 ff 15 ?? ?? ?? ?? 8b 06 68 00 00 aa 00 50 ff 15 } 		$a_01_1 = {74 6f 20 64 65 6c 65 74 65 20 61 20 76 69 72 75 73 } 		$a_01_2 = {57 41 52 4e 49 4e 47 5f 56 49 52 55 53 5f 44 45 54 45 43 54 45 44 0a } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}