rule Trojan_Win32_Trickbot_RTA_MTB_3{
	meta:
		description = "Trojan:Win32/Trickbot.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {c1 e9 02 f3 ab 8b ca 83 e1 03 f3 aa 8d 45 ?? 89 5d ?? 50 53 ff 75 ?? 6a 4c 68 ?? ?? ?? ?? ff 75 ?? e8 ?? ?? ?? ?? 85 c0 5f 74 ?? 8b 45 ?? ff 30 50 ff 75 ?? 53 6a 01 53 ff 75 ?? e8 ?? ?? ?? ?? 85 c0 0f 95 c0 eb ?? 32 c0 } 		$a_01_1 = {79 33 66 70 23 3c 49 4e 36 5a 70 41 5e 29 54 } 	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}