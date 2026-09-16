rule Trojan_Win32_Zenpak_RF_MTB_10{
	meta:
		description = "Trojan:Win32/Zenpak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 38 b8 0f 94 c1 88 8d ?? fe ff ff b8 01 00 00 00 8a 8d ?? fe ff ff f6 c1 01 89 85 ?? fe ff ff 75 ?? eb 90 09 05 00 a1 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}