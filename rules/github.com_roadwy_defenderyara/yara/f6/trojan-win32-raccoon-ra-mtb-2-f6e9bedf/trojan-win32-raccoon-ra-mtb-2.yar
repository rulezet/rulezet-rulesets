rule Trojan_Win32_Raccoon_RA_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 04 8b 4c 24 08 29 08 c2 08 00 55 8b ec 51 83 65 fc 00 8b 45 10 90 01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}