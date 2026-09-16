rule Trojan_Win32_Emotet_GA_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b c8 c6 01 00 8d 49 01 83 ee 01 75 } 		$a_02_1 = {03 c1 83 e0 ?? 0f b6 44 05 ?? 32 42 ?? 88 41 ?? 8b 45 ?? 03 c1 83 e0 ?? 0f b6 44 05 ?? 32 42 ?? 88 41 ?? 8d 04 17 83 c1 04 3d 00 32 02 00 72 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}