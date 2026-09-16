rule Trojan_Win32_Raccoon_RA_MTB_5{
	meta:
		description = "Trojan:Win32/Raccoon.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {36 dd 96 53 81 45 ?? 38 dd 96 53 8b 4d ?? 8b ?? d3 e0 89 45 ?? 8b 45 ?? 01 45 } 		$a_01_1 = {81 00 e1 34 ef c6 c3 01 08 c3 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}