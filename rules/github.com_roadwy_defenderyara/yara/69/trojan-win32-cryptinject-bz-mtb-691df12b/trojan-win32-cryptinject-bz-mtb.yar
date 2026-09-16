rule Trojan_Win32_CryptInject_BZ_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 04 06 33 c9 8a 4d 11 32 c8 51 56 8d 4d f0 e8 ?? ?? ?? ?? 8b 45 f0 b9 ?? ?? ?? ?? 66 0f b6 04 06 03 45 10 69 c0 93 31 00 00 2b c8 8b 45 0c 46 89 4d 10 3b 70 f8 7c c8 } 		$a_01_1 = {73 65 74 20 50 41 53 53 57 44 3d 27 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}