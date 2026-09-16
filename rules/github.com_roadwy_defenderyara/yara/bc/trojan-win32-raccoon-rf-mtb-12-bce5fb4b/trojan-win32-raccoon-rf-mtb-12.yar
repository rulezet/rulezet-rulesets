rule Trojan_Win32_Raccoon_RF_MTB_12{
	meta:
		description = "Trojan:Win32/Raccoon.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {36 dd 96 53 81 44 24 ?? 38 dd 96 53 8b c6 [0-30] 01 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 4c 24 ?? 8b c6 d3 e8 8b 4c 24 ?? 31 4c 24 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}