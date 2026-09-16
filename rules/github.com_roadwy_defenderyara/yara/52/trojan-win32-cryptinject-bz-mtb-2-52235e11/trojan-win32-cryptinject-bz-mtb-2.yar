rule Trojan_Win32_CryptInject_BZ_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 8c 30 3b 2d 0b 00 8b 15 ?? ?? ?? ?? 88 0c 32 81 3d ?? ?? ?? ?? 37 0d 00 00 75 } 		$a_02_1 = {8b c7 d3 e0 8b cf c1 e9 05 03 4d e4 03 45 d8 89 15 ?? ?? ?? ?? 33 c1 8b 4d f0 03 cf 33 c1 29 45 f8 a1 ?? ?? ?? ?? 3d d5 01 00 00 75 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}