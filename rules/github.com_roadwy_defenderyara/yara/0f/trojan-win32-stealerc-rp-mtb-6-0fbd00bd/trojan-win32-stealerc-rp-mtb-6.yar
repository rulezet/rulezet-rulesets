rule Trojan_Win32_Stealerc_RP_MTB_6{
	meta:
		description = "Trojan:Win32/Stealerc.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ba 61 2a 07 [0-04] 9c 16 00 48 [0-04] 4d 4f 3f 0a [0-04] da 50 d8 1b [0-04] ca b6 35 54 [0-04] 65 58 8c 69 [0-04] 52 8b 07 25 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}