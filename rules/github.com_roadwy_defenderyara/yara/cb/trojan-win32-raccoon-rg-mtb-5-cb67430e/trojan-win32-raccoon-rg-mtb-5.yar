rule Trojan_Win32_Raccoon_RG_MTB_5{
	meta:
		description = "Trojan:Win32/Raccoon.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {36 dd 96 53 81 44 24 ?? 38 dd 96 53 8b 4c 24 ?? 8b d6 d3 e2 [0-30] 8b c6 d3 e8 03 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 ?? 31 4c 24 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}