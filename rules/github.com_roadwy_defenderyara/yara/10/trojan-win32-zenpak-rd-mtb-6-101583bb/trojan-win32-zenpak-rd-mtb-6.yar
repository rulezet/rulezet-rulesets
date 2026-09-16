rule Trojan_Win32_Zenpak_RD_MTB_6{
	meta:
		description = "Trojan:Win32/Zenpak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b9 89 88 88 88 89 84 24 ?? ?? 00 00 f7 e1 c1 ea 03 6b c2 0f 8b 8c 24 ?? ?? 00 00 29 c1 89 c8 83 e8 06 89 4c 24 ?? 89 44 24 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}