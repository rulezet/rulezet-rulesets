rule Trojan_Win32_Emotet_G_2{
	meta:
		description = "Trojan:Win32/Emotet.G,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {f7 f1 8a 0c 15 ?? ?? ?? ?? 89 7c 24 ?? 8b 54 24 ?? 8a 2c 1a 8b 7c 24 ?? 8b 54 24 ?? 29 d7 89 7c 24 ?? 28 cd 80 f5 ?? 8b 7c 24 ?? 89 7c 24 ?? 8b 54 24 ?? 88 2c 1a 01 f3 89 5c 24 ?? 8b 74 24 ?? 39 f3 72 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}