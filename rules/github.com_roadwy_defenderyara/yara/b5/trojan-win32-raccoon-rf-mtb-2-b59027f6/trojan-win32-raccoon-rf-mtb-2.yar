rule Trojan_Win32_Raccoon_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 c0 8b 55 e4 8d 4d f8 89 0c 24 8b 4d 14 8b 5d 0c 33 99 20 01 00 00 89 5c 24 04 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}