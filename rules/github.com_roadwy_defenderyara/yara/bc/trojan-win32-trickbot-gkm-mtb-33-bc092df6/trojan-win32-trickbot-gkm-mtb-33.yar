rule Trojan_Win32_Trickbot_GKM_MTB_33{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {8a 01 8a 14 37 88 04 37 88 11 49 47 3b 7d 08 7e } 		$a_02_1 = {85 c0 59 75 ?? 8b 45 ?? 0f b7 00 8b 3c 83 03 7d ?? ff 45 ?? 83 45 ?? 04 8b 45 ?? 83 45 ?? 02 3b 46 ?? 72 } 		$a_00_2 = {53 74 75 70 69 64 20 77 69 6e 64 6f 77 73 20 64 65 66 65 6e 64 65 72 } 		$a_00_3 = {61 6d 75 4e 78 45 63 6f 6c 6c 41 6c 61 75 74 72 69 56 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}