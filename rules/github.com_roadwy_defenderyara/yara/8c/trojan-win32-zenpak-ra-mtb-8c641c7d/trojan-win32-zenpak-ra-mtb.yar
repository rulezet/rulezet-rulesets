rule Trojan_Win32_Zenpak_RA_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 44 24 24 f7 e1 c1 ea 08 69 c2 41 01 00 00 8b 4c 24 24 29 c1 89 c8 83 e8 05 89 4c 24 20 89 44 24 1c } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}