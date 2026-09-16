rule Trojan_Win32_IcedId_SIBK_MTB_2{
	meta:
		description = "Trojan:Win32/IcedId.SIBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 31 48 c1 e2 ?? 48 0b c2 4c 8b c0 33 c9 b8 01 00 00 00 0f a2 89 44 24 ?? 89 5c 24 ?? 89 4c 24 ?? 89 54 24 ?? 0f 31 48 c1 e2 ?? 48 0b c2 49 2b c0 48 03 f8 ff 15 ?? ?? ?? ?? 0f 31 48 c1 e2 ?? 90 90 48 0b c2 48 8b c8 0f 31 48 c1 e2 ?? 48 0b c2 48 2b c1 48 03 f0 48 83 ed ?? 75 } 		$a_03_1 = {45 33 c0 4c 8d 0d ?? ?? ?? ?? 49 2b c9 4b 8d 14 08 49 ff c0 8a 42 ?? 32 02 88 44 11 ?? 49 83 f8 ?? 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}