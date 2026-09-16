rule Trojan_Win32_Zenpak_RG_MTB_7{
	meta:
		description = "Trojan:Win32/Zenpak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe ff ff 89 c1 88 ca 83 e8 4d 88 95 ?? fe ff ff 89 85 ?? fe ff ff 74 ?? eb 00 8a 85 ?? fe ff ff 0f b6 c8 83 e9 54 89 8d ?? fe ff ff 74 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}