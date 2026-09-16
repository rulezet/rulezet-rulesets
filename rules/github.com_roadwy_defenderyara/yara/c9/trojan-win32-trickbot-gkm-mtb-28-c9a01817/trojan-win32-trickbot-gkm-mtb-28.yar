rule Trojan_Win32_Trickbot_GKM_MTB_28{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 04 33 f6 d0 8b ce 3b f7 73 ?? eb ?? 8d 49 00 8a d9 2a da 32 19 32 d8 88 19 03 4d ?? 3b cf 72 ?? 8b 5d ?? 46 ff 4d ?? 75 } 		$a_00_1 = {45 46 6f 71 65 6b 6b 6b 42 43 65 67 41 72 62 67 72 6d 47 72 6d 67 74 47 47 6d 6b 61 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}