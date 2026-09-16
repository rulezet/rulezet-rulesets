rule Trojan_Win32_Stealerc_RP_MTB_8{
	meta:
		description = "Trojan:Win32/Stealerc.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 0c ba 61 2a 07 c7 44 24 24 9c 16 00 48 c7 44 24 14 4d 4f 3f 0a c7 44 24 1c da 50 d8 1b c7 44 24 10 ca b6 35 54 c7 44 24 28 65 58 8c 69 c7 44 24 5c 52 8b 07 25 c7 44 24 58 50 b5 81 09 c7 44 24 34 8e 34 a6 6e c7 44 24 30 52 f3 6c 10 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}