rule Trojan_Win32_Emotet_PAH_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.PAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 00 50 e8 ?? ?? ?? ?? 8b 4c 24 ?? 8b 44 24 ?? 8b 35 ?? ?? ?? ?? 8b d1 2b 15 ?? ?? ?? ?? 41 03 c2 0f b6 54 ?? ?? 8a 14 32 30 10 3b 4c 24 ?? 89 4c 24 ?? 0f 8c ?? ?? ?? ?? 8a 4c 24 ?? 8b 44 ?? 24 8a 54 24 ?? 5f 5e 5d 5b 88 50 ?? 88 08 83 c4 08 c3 } 		$a_03_1 = {99 f7 fb 8a c2 88 45 ?? 0f b6 c0 89 45 ?? 03 c1 50 57 e8 } 		$a_03_2 = {99 f7 f9 0f b6 c2 8a 04 38 30 03 8b 45 ?? 8b 5d ?? 3b 75 ?? 7c [0-04] 8b 75 ?? 8a 45 ?? 5f 5b 88 06 8a 45 ?? 88 46 ?? 5e 8b e5 5d c3 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}