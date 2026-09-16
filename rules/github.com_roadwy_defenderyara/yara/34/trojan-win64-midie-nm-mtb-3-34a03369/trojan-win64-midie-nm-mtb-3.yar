rule Trojan_Win64_Midie_NM_MTB_3{
	meta:
		description = "Trojan:Win64/Midie.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 8b cb 33 c9 ff 15 ee 35 06 00 48 8b f8 48 85 c0 74 12 48 8b c8 48 89 43 ?? ff 15 e9 35 06 00 83 f8 ff 75 37 } 		$a_03_1 = {53 48 83 ec ?? 4c 8b c1 33 d2 48 8b 0d de ce 05 00 ff 15 98 72 02 00 85 c0 75 16 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}