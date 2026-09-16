rule Trojan_Win32_Zenpak_RI_MTB_4{
	meta:
		description = "Trojan:Win32/Zenpak.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e1 8b 44 24 ?? 29 d0 d1 e8 01 d0 c1 e8 04 6b c0 13 8b 4c 24 ?? 29 c1 89 c8 83 e8 07 89 4c 24 ?? 89 44 24 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}