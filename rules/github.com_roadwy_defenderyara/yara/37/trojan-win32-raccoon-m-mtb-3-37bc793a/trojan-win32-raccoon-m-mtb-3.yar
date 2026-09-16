rule Trojan_Win32_Raccoon_M_MTB_3{
	meta:
		description = "Trojan:Win32/Raccoon.M!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {51 c7 04 24 02 00 00 00 8b 44 24 0c 01 04 24 83 2c 24 02 8b 44 24 08 8b 0c 24 31 08 59 c2 08 00 8b 4c 24 04 8b 01 89 44 24 04 8b 44 24 08 90 01 44 24 04 8b 54 24 04 89 11 c2 08 00 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}