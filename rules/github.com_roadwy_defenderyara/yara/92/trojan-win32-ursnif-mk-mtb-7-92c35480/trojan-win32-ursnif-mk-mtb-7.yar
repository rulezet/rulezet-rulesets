rule Trojan_Win32_Ursnif_MK_MTB_7{
	meta:
		description = "Trojan:Win32/Ursnif.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 6c 24 1c 4e 8d 84 30 ?? ?? ?? ?? 0f b7 d0 8a 04 2f 88 07 89 54 24 10 8b 15 ?? ?? ?? ?? 47 3b d3 77 1e 0f b6 c1 66 0f b6 c9 66 03 cb 66 83 e9 ?? 66 01 4c 24 10 8a 4c 24 10 a3 ?? ?? ?? ?? 2a cb 0f b7 6c 24 10 8b 44 24 14 2b c5 03 c6 3b d3 77 12 0f b6 d1 89 15 90 1b 03 8a d0 2a d3 80 ea ?? 02 ca 85 f6 75 98 } 		$a_03_1 = {3b 05 d0 00 03 10 74 1a 8b 15 ?? ?? ?? ?? 29 11 8b f2 69 f6 ?? ?? 00 00 2b f0 8b c6 03 d0 8d 5c 13 ca 83 e9 08 81 f9 ?? ?? ?? ?? 7f d3 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}