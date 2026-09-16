rule Trojan_Win32_CryptInject_AP_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {56 33 f6 85 d2 7e 0d e8 ?? ?? ff ff 30 04 0e 46 3b f2 7c f3 5e c3 } 		$a_02_1 = {c1 e8 10 25 ff 7f 00 00 c3 90 0a 4f 00 69 05 ?? ?? ?? 00 ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? 00 c1 e8 10 25 ff 7f 00 00 c3 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}