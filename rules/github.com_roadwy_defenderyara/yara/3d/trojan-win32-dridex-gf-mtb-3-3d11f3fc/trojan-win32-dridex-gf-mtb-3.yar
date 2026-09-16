rule Trojan_Win32_Dridex_GF_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_02_0 = {89 14 24 89 44 24 ?? c7 44 24 ?? ?? ?? ?? ?? 89 74 24 ?? 89 4c 24 ?? e8 } 		$a_02_1 = {40 cc cc cc eb ?? 8b 04 24 64 a3 00 00 00 00 83 c4 08 eb ?? 8b 44 24 ?? ff 80 ?? ?? ?? ?? 31 c0 c3 c3 } 		$a_02_2 = {8b 04 24 64 a3 00 00 00 00 83 c4 08 eb ?? 8b 44 24 ?? ff 80 ?? ?? ?? ?? 31 c0 c3 c3 90 0a 23 00 cc cc cc 40 eb } 		$a_80_3 = {74 74 74 74 33 32 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*5+(#a_02_2  & 1)*5+(#a_80_3  & 1)*10) >=16
 
}