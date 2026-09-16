rule Trojan_Win32_Trickbot_BA_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {76 74 49 40 25 39 49 65 40 55 76 7c 54 65 4e 25 72 6e 7d 23 } 		$a_02_1 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 10 8d 0c 06 33 d2 6a 14 8b c6 5b f7 f3 8b 44 24 0c 8a 04 02 30 01 46 3b 74 24 14 75 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}