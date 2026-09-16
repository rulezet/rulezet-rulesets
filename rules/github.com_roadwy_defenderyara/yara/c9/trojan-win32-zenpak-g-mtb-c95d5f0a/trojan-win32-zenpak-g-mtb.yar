rule Trojan_Win32_Zenpak_G_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e8 8b 4d ec 8a 14 01 8b 45 e8 8b 4d f0 88 14 01 8b 45 e8 05 01 00 00 00 89 45 e8 eb c9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}