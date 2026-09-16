rule Trojan_Win32_Raccoon_RF_MTB_5{
	meta:
		description = "Trojan:Win32/Raccoon.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 04 8b 4c 24 08 29 08 c2 08 00 8b 44 24 04 8b 4c 24 08 29 08 c2 08 00 8b 44 24 08 33 44 24 0c 8b 4c 24 04 89 01 c2 0c 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}