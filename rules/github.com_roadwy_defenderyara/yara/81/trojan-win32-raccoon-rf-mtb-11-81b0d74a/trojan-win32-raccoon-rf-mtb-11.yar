rule Trojan_Win32_Raccoon_RF_MTB_11{
	meta:
		description = "Trojan:Win32/Raccoon.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 45 fc 83 6d fc 02 8b 45 08 8b 4d fc 31 08 c9 c2 08 00 8b 44 24 04 8b 4c 24 08 01 08 c2 08 00 55 8b ec 51 83 65 fc 00 83 45 fc 04 8b 4d fc 8b 45 0c d3 e0 8b 4d 08 89 01 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}