rule Trojan_Win32_Zenpak_RC_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e1 c1 ea 02 6b c2 12 8b 4c 24 ?? 29 c1 89 c8 83 e8 07 89 4c 24 ?? 89 44 24 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}