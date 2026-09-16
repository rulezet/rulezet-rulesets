rule Trojan_Win32_RedLine_RPX_MTB_8{
	meta:
		description = "Trojan:Win32/RedLine.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c2 50 ff 74 24 50 ff 54 24 34 8b 44 24 18 47 8b 54 24 14 83 c6 28 0f b7 80 ?? ?? ?? ?? 3b f8 7c bc 8b 7c 24 2c 8b 74 24 1c 8b 86 a4 00 00 00 6a 00 6a 04 ff 74 24 44 83 c0 08 50 ff 74 24 50 ff 54 24 34 8b 4c 24 18 56 8b 81 ?? ?? ?? ?? 03 44 24 18 89 86 b0 00 00 00 ff 74 24 48 ff 54 24 38 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}