rule Trojan_Win32_Zenpak_RD_MTB_7{
	meta:
		description = "Trojan:Win32/Zenpak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 c0 b9 90 00 00 00 8d 54 24 20 be 60 00 00 00 8d bc 24 68 02 00 00 89 3c 24 c7 44 24 04 00 00 00 00 c7 44 24 08 60 00 00 00 89 44 24 1c 89 4c 24 18 89 54 24 14 89 74 24 10 e8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}