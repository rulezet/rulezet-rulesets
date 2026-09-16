rule Trojan_Win32_Zenpak_RI_MTB_5{
	meta:
		description = "Trojan:Win32/Zenpak.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 84 24 a8 00 00 00 b9 39 8e e3 38 89 84 24 a4 00 00 00 f7 e1 c1 ea 02 6b c2 12 8b 8c 24 a4 00 00 00 29 c1 89 c8 83 e8 0b 89 8c 24 a0 00 00 00 89 84 24 9c 00 00 00 74 7f } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}