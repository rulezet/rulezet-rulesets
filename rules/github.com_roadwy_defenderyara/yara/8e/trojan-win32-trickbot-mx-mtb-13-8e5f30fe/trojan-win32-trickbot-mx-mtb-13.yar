rule Trojan_Win32_Trickbot_MX_MTB_13{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 c4 2c 8a 8c 15 ?? ?? ?? ?? 30 08 40 83 7d 10 00 89 85 ?? ?? ?? ?? 0f 85 } 		$a_80_1 = {34 54 76 46 50 41 44 36 54 78 4d 79 58 36 7a 67 58 61 6b 62 4d 51 74 51 75 6c 59 53 54 47 6d 68 71 79 34 71 } 	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}