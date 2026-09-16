rule Trojan_Win32_Killav_BS{
	meta:
		description = "Trojan:Win32/Killav.BS,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {50 53 53 8d 45 ?? 6a 04 50 68 4b e1 22 00 } 		$a_03_1 = {8b 51 04 8d 41 08 89 45 08 89 5d ?? 8d 42 f8 89 5d fc d1 e8 89 45 ?? 74 43 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}