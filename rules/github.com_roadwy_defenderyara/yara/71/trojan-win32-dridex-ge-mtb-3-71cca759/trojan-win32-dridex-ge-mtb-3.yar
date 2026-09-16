rule Trojan_Win32_Dridex_GE_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_02_0 = {29 c3 88 d8 88 45 ?? 8b 5d ?? 8b 45 ?? 89 45 ?? 8a 45 ?? 8b 7d ?? 88 04 3b 89 75 ?? 89 4d ?? 89 55 ?? 83 c4 } 		$a_02_1 = {66 8b 54 24 04 66 81 c2 32 7b 66 89 54 24 ?? 8a 5c 24 ?? 88 1c 01 8d 65 f4 5f 5e } 		$a_02_2 = {40 cc cc cc eb ?? 8b 04 24 64 a3 00 00 00 00 83 c4 08 eb ?? 8b 44 24 ?? ff 80 ?? ?? ?? ?? 31 c0 c3 c3 } 		$a_02_3 = {8b 04 24 64 a3 00 00 00 00 83 c4 08 eb ?? 8b 44 24 ?? ff 80 ?? ?? ?? ?? 31 c0 c3 c3 90 0a 23 00 cc cc cc 40 eb } 		$a_80_4 = {74 74 74 74 33 32 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*5+(#a_02_3  & 1)*5+(#a_80_4  & 1)*10) >=16
 
}