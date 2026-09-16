rule Trojan_Win32_Emotet_RTH_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {64 2b 25 37 46 4d 38 4d 55 65 53 48 30 5f 78 48 34 29 4c 71 46 6c 36 44 5e 44 37 77 73 71 6b 34 4a 78 69 50 71 30 56 6d 40 24 3f 38 6d 4d 26 53 6a 43 3c 58 51 39 66 37 4c 74 2b 4b 62 3e 53 52 4a 51 39 } 		$a_03_1 = {2b d1 2b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 8b 4d ?? 0f b6 14 11 8b 4d ?? 0f b6 04 01 33 c2 8b 4d ?? 2b 0d ?? ?? ?? ?? 8b 55 ?? 88 04 0a } 	condition:
		((#a_81_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}