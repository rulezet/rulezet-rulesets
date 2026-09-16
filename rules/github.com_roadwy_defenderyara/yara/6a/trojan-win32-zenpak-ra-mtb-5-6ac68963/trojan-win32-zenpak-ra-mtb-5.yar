rule Trojan_Win32_Zenpak_RA_MTB_5{
	meta:
		description = "Trojan:Win32/Zenpak.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e0 c7 40 14 57 03 00 00 c7 40 10 57 03 00 00 c7 40 0c 57 03 00 00 c7 40 08 57 03 00 00 c7 40 04 57 03 00 00 c7 00 57 03 00 00 a1 ?? ?? ?? ?? ff d0 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}