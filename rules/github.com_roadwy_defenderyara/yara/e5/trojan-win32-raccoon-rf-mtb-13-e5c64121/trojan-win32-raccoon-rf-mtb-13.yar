rule Trojan_Win32_Raccoon_RF_MTB_13{
	meta:
		description = "Trojan:Win32/Raccoon.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {36 dd 96 53 81 45 ?? 38 dd 96 53 8b 4d ?? 8b c7 d3 e0 [0-30] 8b c7 d3 e8 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}