rule Trojan_Win32_Zenpak_RF_MTB_4{
	meta:
		description = "Trojan:Win32/Zenpak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b9 89 88 88 88 89 45 ?? f7 e1 c1 ea 03 6b c2 0f 8b 4d ?? 29 c1 89 c8 83 e8 ?? 89 4d ?? 89 45 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}