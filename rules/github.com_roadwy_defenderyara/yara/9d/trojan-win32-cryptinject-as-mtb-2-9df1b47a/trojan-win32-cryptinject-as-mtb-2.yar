rule Trojan_Win32_CryptInject_AS_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 45 e4 40 89 45 ?? 8b 45 ?? 3b 05 ?? ?? ?? ?? 73 ?? a1 ?? ?? ?? ?? 89 45 ?? b8 ?? ?? ?? ?? 01 45 ?? a1 ?? ?? ?? ?? 03 45 ?? 8b 4d ?? 03 4d ?? 8a 09 88 08 eb } 		$a_00_1 = {69 c9 fd 43 03 00 81 c1 c3 9e 26 00 8b c1 c1 e8 10 30 04 1e 46 3b f7 7c e7 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}