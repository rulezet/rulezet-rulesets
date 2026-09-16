rule Trojan_Win32_RedLine_RPX_MTB_5{
	meta:
		description = "Trojan:Win32/RedLine.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b f0 8b 0e 8b 49 04 8b 4c 31 30 8b 49 04 89 4c 24 0c 8b 11 ff 52 04 8d 44 24 08 50 e8 ?? ?? ?? ?? 83 c4 04 8b 08 6a 0a 8b 51 30 8b c8 ff d2 8b 4c 24 0c 0f b7 f8 85 c9 74 13 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}