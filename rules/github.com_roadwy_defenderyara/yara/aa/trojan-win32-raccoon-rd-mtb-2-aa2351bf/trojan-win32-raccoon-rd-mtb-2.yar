rule Trojan_Win32_Raccoon_RD_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 45 fc 83 6d fc 02 8b 45 08 8b 4d fc 31 08 c9 c2 08 00 8b 44 24 04 8b 4c 24 08 01 08 c2 08 00 8b 44 24 08 8b 4c 24 04 c1 e0 04 89 01 c2 08 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}