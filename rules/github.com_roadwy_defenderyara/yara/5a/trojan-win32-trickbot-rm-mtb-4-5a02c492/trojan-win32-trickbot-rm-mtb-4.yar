rule Trojan_Win32_Trickbot_RM_MTB_4{
	meta:
		description = "Trojan:Win32/Trickbot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {ff 30 50 ff 75 ?? 53 6a 01 53 ff 75 ?? ff 55 ?? 85 c0 0f 95 c0 eb ?? 32 c0 } 		$a_02_1 = {59 33 c0 bf e0 73 48 00 39 75 ?? f3 ab aa 89 1d ?? ?? ?? ?? 0f 86 ?? ?? ?? ?? 80 7d ?? 00 0f 84 ?? ?? ?? ?? 8d 4d ?? 8a 11 84 d2 0f 84 } 		$a_01_2 = {36 49 68 4e 39 47 44 72 23 61 4b 2b 61 73 4b } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}