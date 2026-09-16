rule Trojan_Win32_Trickbot_A_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 } 		$a_00_1 = {6b 00 6c 00 59 00 4b 00 41 00 6e 00 4d 00 2e 00 65 00 78 00 65 00 } 		$a_02_2 = {8b c1 33 d2 f7 f7 41 8a 82 ?? ?? ?? 00 30 44 31 ff 81 f9 ?? ?? 00 00 75 e7 eb } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}