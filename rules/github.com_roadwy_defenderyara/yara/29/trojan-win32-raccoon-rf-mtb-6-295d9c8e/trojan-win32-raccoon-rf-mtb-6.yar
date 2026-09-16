rule Trojan_Win32_Raccoon_RF_MTB_6{
	meta:
		description = "Trojan:Win32/Raccoon.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {51 c7 04 24 00 00 00 00 8b 44 24 0c 89 04 24 8b 44 24 08 31 04 24 8b 04 24 89 01 59 c2 08 00 [0-08] 81 00 e1 34 ef c6 c3 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}