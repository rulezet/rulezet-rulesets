rule Trojan_Win32_Zenpak_RF_MTB_5{
	meta:
		description = "Trojan:Win32/Zenpak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b9 89 88 88 88 89 44 24 ?? f7 e1 c1 ea 03 6b c2 0f 8b 4c 24 ?? 29 c1 83 c9 04 83 e9 07 89 4c 24 ?? 74 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}