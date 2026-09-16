rule Trojan_Win32_Zenpak_RG_MTB_4{
	meta:
		description = "Trojan:Win32/Zenpak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b9 cd cc cc cc 89 44 24 ?? f7 e1 c1 ea 04 6b c2 14 8b 4c 24 ?? 29 c1 89 c8 83 e8 07 89 4c 24 ?? 89 44 24 ?? 74 35 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}