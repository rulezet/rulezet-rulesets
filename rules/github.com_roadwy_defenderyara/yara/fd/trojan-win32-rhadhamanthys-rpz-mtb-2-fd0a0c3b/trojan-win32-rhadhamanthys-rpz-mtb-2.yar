rule Trojan_Win32_Rhadhamanthys_RPZ_MTB_2{
	meta:
		description = "Trojan:Win32/Rhadhamanthys.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 44 24 0c 8b 4c 24 28 8b 54 24 24 89 44 11 04 8b 44 24 20 8b 40 08 8b 4c 24 28 8b 54 24 24 83 c2 04 01 d1 8b 54 24 20 89 14 24 89 4c 24 04 ff d0 89 44 24 40 8a 44 24 0b 04 01 88 44 24 0b 8b 44 24 40 8b 4c 24 14 0f b6 54 24 0b 89 04 91 8b 44 24 28 8b 4c 24 24 8b 04 08 89 44 24 0c eb 41 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}