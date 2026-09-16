rule Backdoor_Win32_IRCBot_TA_2{
	meta:
		description = "Backdoor:Win32/IRCBot.TA,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {5b 64 64 6f 73 5d 3a } 		$a_01_1 = {53 6c 6f 77 6c 6f 72 69 73 20 61 74 74 61 63 6b 28 29 } 		$a_01_2 = {5b 53 55 50 45 52 53 59 4e 5d 20 44 6f 6e 65 20 77 69 74 68 20 66 6c 6f 6f 64 } 		$a_01_3 = {5b 55 53 42 5d 2d 2d 3e 5b 25 73 5d } 		$a_01_4 = {5b 4c 41 4e 5d 2d 2d 3e 5b 25 73 5d } 		$a_03_5 = {0f be 00 83 e8 4e 99 b9 1a 00 00 00 f7 f9 83 c2 61 ?? ?? ?? ?? ?? ?? 88 10 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*5) >=8
 
}