rule Trojan_Win32_CryptInject_PF_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {87 ff 8b 1c 0a 49 41 ?? ?? 81 f3 ?? ?? ?? ?? 49 41 87 ff 89 1c 08 49 41 ?? ?? 83 c1 04 49 41 c1 e9 00 81 f9 ?? ?? 00 00 75 d4 87 ff 49 41 ff e0 } 		$a_02_1 = {87 ff 49 41 8b 1c 0a c1 e6 00 87 ff 81 f3 ?? ?? ?? ?? c1 e6 00 49 41 89 1c 08 c1 e6 00 87 ff 83 c1 04 c1 e6 00 ?? ?? 81 f9 ?? ?? 00 00 75 d1 49 41 c1 e6 00 ff e0 } 		$a_02_2 = {87 ff 49 41 c1 e6 00 8b 1c 0a c1 e6 00 87 ff 81 f3 ?? ?? ?? ?? c1 e6 00 49 41 89 1c 08 c1 e6 00 87 ff 83 c1 04 c1 e6 00 ?? ?? 81 f9 ?? ?? 00 00 75 d0 49 41 c1 e6 00 ff e0 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}