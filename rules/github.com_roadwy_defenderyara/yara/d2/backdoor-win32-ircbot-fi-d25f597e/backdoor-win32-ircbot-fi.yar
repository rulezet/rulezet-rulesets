rule Backdoor_Win32_IRCbot_FI{
	meta:
		description = "Backdoor:Win32/IRCbot.FI,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {75 70 64 61 74 65 2e 62 71 6c 61 62 2e 63 6f 6d } 		$a_01_1 = {76 69 62 6f 74 } 		$a_01_2 = {66 6c 6f 6f 64 20 6f 6e 20 25 73 3a 25 73 20 66 6f 72 20 25 73 20 73 65 63 6f 6e 64 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}