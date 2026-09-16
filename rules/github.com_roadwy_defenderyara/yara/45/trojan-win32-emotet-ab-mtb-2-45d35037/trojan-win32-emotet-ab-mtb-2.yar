rule Trojan_Win32_Emotet_AB_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_02_0 = {81 f1 ed b5 77 61 89 45 ?? 8b 45 ?? 8b 55 ?? 8a 1c 02 8b 45 ?? 88 5d ?? 39 c8 74 } 		$a_02_1 = {8a 14 01 8b 75 ?? 88 14 06 83 c0 01 8b 7d ?? 39 f8 89 45 ?? 75 90 09 06 00 8b 45 ?? 8b 4d f0 } 		$a_02_2 = {81 f1 fb 0d eb 6e 8b 55 ?? 8a 1c 02 8b 75 ?? 88 1c 06 01 c8 8b 4d ?? 39 c8 89 45 ?? 74 } 		$a_02_3 = {8a 1c 02 8b 44 24 ?? 88 1c 08 8b 4c 24 ?? 83 c1 01 89 4c 24 ?? 8b 74 24 ?? 39 f1 74 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=1
 
}