rule Trojan_Win32_Gozi_RA_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 04 0a 8b f8 85 c0 75 0a c7 44 24 10 01 00 00 00 eb 0d 2b 74 24 0c 03 c6 89 01 8b f7 83 c1 04 ff 4c 24 10 75 da } 		$a_01_1 = {8b 4d e0 8b 41 0c 2b 41 08 81 45 f8 00 10 00 00 03 41 04 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}