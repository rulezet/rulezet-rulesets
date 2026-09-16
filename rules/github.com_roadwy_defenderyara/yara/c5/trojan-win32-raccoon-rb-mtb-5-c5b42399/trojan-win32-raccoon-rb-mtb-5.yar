rule Trojan_Win32_Raccoon_RB_MTB_5{
	meta:
		description = "Trojan:Win32/Raccoon.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 83 65 fc 00 8b 45 10 01 45 fc 8b 45 0c 33 45 fc 89 45 fc 8b 45 08 8b 4d fc 89 08 c9 c2 0c 00 [0-25] 55 8b ec 51 c7 45 fc 02 00 00 00 83 45 fc 02 8b 4d fc 8b 45 0c d3 e0 8b 4d 08 89 01 c9 c2 08 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}