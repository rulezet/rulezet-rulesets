rule Trojan_Win32_Raccoon_RA_MTB_3{
	meta:
		description = "Trojan:Win32/Raccoon.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 45 fc 8b 45 08 8b 4d fc 31 08 c9 c2 08 00 [0-30] 55 8b ec 8b 4d 08 8b 01 89 45 08 8b 45 0c 01 45 08 8b 45 08 89 01 5d c2 08 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}