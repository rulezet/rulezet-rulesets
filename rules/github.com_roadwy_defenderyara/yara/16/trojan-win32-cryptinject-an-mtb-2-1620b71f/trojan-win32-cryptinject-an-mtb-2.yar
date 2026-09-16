rule Trojan_Win32_CryptInject_AN_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 10 03 f1 8b 08 13 ea 8b c7 6b c0 ?? 81 7c 24 18 ?? ?? ?? ?? 89 0d ?? ?? ?? 00 8d 0c 18 } 		$a_02_1 = {8b 44 24 1c 13 c2 8b f3 8b e8 0f b6 0d ?? ?? ?? 00 a1 ?? ?? ?? 00 8b 54 24 10 05 ?? ?? ?? ?? 8d 1c b9 a3 ?? ?? ?? 00 89 02 8d 44 1b ec } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}