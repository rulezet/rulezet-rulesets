rule Trojan_Win32_Dridex_DD_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 16 01 d1 8b 55 ?? 81 ea ?? ?? ?? ?? 89 c8 89 55 ?? 99 8b 4d ?? f7 f9 8b 75 ?? 89 16 8b 55 ?? 8b 0a 8b 55 ?? 8b 12 0f b6 0c 0a 8b 16 8b 75 ?? 8b 36 0f b6 14 16 31 d1 8b 55 ?? 8b 32 8b 55 c4 8b 12 88 0c 32 } 		$a_03_1 = {0f b6 14 16 8b 75 ?? 8b 7d ?? 0f b6 34 37 01 f2 89 d0 99 f7 f9 89 55 ?? 8b 55 ?? 8b 75 ?? 0f b6 14 16 8b 75 ?? 8b 7d ?? 0f b6 34 37 31 f2 88 d3 8b 55 ?? 8b 75 ?? 88 1c 16 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}