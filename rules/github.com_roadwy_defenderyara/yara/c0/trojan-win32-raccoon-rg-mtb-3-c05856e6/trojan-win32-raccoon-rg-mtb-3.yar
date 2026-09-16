rule Trojan_Win32_Raccoon_RG_MTB_3{
	meta:
		description = "Trojan:Win32/Raccoon.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 08 89 54 24 04 c7 04 24 00 00 00 00 8b 44 24 0c 89 04 24 8b 44 24 04 31 04 24 8b 04 24 89 01 83 c4 08 c2 04 00 [0-10] 81 01 e1 34 ef c6 c3 [0-10] 29 11 c3 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}