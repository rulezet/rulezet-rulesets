rule Trojan_Win32_CryptInject_BG_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_00_0 = {03 55 10 8b 45 10 8a 92 85 c5 0a 00 88 14 01 } 		$a_02_1 = {d3 ea 89 55 e0 8b 45 e0 03 45 a8 89 45 e0 8b 4d ec 33 4d b8 89 4d ec 81 3d ?? ?? ?? ?? c1 10 00 00 75 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*2) >=3
 
}