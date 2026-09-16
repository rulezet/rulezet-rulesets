rule Trojan_Win32_CryptInject_PZ_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 84 24 40 01 00 00 48 8d 0d ?? ?? ?? ?? 8a 04 08 88 84 24 38 01 00 00 0f b6 84 24 38 01 00 00 42 0f b6 04 00 0f b6 8c 24 30 01 00 00 33 c8 8b 84 24 40 01 00 00 88 4c 04 20 8a 84 24 30 01 00 00 fe c0 88 84 24 30 01 00 00 8b 84 24 40 01 00 00 ff c0 89 84 24 40 01 00 00 8b 84 24 40 01 00 00 41 3b c2 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}