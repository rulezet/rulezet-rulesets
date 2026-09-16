rule Trojan_Win32_Raccoon_RF_MTB_8{
	meta:
		description = "Trojan:Win32/Raccoon.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 08 89 55 f8 89 4d fc 8b 45 f8 c1 e0 04 8b 4d fc 89 01 8b e5 5d c3 [0-20] 8b 08 81 e9 1f cb 10 39 8b 55 fc 89 0a 8b e5 5d c3 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}