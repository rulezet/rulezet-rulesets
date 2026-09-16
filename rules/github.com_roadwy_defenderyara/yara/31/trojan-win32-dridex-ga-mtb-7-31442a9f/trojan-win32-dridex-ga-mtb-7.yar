rule Trojan_Win32_Dridex_GA_MTB_7{
	meta:
		description = "Trojan:Win32/Dridex.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_02_0 = {89 fa 81 f2 ?? ?? ?? ?? 89 54 24 ?? 89 5c 24 ?? 0f b6 04 08 89 c1 0f b6 55 ?? 29 d0 88 c5 89 5c 24 ?? 89 7c 24 ?? 88 6c 24 ?? 8b 45 ?? 8b 55 ?? 8a 6c 24 ?? 80 f1 ff 88 4c 24 ?? 88 2c 10 89 74 24 ?? 8d 65 } 		$a_02_1 = {cc cc 40 cc eb ?? 8b 04 24 64 a3 00 00 00 00 83 c4 08 eb ?? 8b 44 24 ?? ff 80 ?? ?? ?? ?? 31 c0 c3 c3 } 		$a_80_2 = {74 74 74 74 33 32 } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_80_2  & 1)*10) >=30
 
}