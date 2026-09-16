rule Trojan_Win32_Raccoon_RJ_MTB_3{
	meta:
		description = "Trojan:Win32/Raccoon.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 00 47 86 c8 61 c3 81 00 e1 34 ef c6 c3 01 08 c3 } 		$a_03_1 = {03 c6 89 45 ?? 8b c6 d3 e8 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 33 45 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}