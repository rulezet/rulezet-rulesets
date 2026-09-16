rule Trojan_Win32_Stealerc_RP_MTB_5{
	meta:
		description = "Trojan:Win32/Stealerc.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 08 ba 61 2a 07 c7 44 24 20 9c 16 00 48 c7 44 24 10 4d 4f 3f 0a c7 44 24 18 da 50 d8 1b c7 44 24 0c ca b6 35 54 c7 44 24 24 65 58 8c 69 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}