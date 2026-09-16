rule Trojan_Win32_Zenpak_RA_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {21 f1 8b 75 ec 8b 5d d0 8a 34 1e 32 34 0f 8b 4d e8 88 34 19 8b 4d c0 8b 75 f0 39 f1 8b 4d b8 8b 75 b0 8b 7d c0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}