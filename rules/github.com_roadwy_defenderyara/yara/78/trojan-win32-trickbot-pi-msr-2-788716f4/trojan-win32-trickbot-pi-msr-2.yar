rule Trojan_Win32_Trickbot_PI_MSR_2{
	meta:
		description = "Trojan:Win32/Trickbot.PI!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {50 68 60 11 00 00 57 53 e8 ?? ?? ff ff 83 c4 10 6a 40 68 00 10 00 00 ff 75 fc 6a 00 e8 ?? ?? 00 00 89 45 f0 ff 75 fc ff 75 f8 ff 75 f0 e8 ?? ?? 00 00 83 c4 0c 6a 40 68 00 10 00 00 68 60 11 00 00 6a 00 e8 ?? ?? 00 00 8b f8 68 60 11 00 00 53 57 e8 ?? ?? 00 00 83 c4 0c 8d 45 fc 50 ff 75 f0 6a 10 ff 75 ec ff d7 } 		$a_00_1 = {5f 5f 5f 43 50 50 64 65 62 75 67 48 6f 6f 6b } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}