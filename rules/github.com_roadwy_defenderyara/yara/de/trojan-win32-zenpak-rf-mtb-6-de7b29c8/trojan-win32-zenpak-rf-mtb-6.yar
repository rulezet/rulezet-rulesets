rule Trojan_Win32_Zenpak_RF_MTB_6{
	meta:
		description = "Trojan:Win32/Zenpak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 8b 55 ?? f7 e2 c1 ea 02 6b c2 12 29 c1 89 c8 83 e8 02 89 4d ?? 89 45 ?? 0f 84 ?? ?? ff ff eb 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}