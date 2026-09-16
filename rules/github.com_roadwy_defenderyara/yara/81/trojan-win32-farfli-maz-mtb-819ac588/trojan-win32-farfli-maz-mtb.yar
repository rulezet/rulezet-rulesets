rule Trojan_Win32_Farfli_MAZ_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {89 45 e0 8b 0d ?? ?? ?? ?? 89 4d e4 8b 15 ?? ?? ?? ?? 89 55 e8 a1 ?? ?? ?? ?? 89 45 ec 8a 0d ?? ?? ?? ?? 88 4d f0 8d 55 e0 52 e8 ?? ?? ?? ?? 83 c4 04 50 68 } 		$a_01_1 = {4b 79 64 68 48 78 38 36 63 32 45 6d 49 69 42 44 } 		$a_01_2 = {38 76 54 32 43 51 59 4c 43 7a 6f 2d } 		$a_01_3 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}