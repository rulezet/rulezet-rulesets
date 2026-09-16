rule Trojan_Win32_IcedID_MB_MTB{
	meta:
		description = "Trojan:Win32/IcedID.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {2b df 81 c1 20 f3 8e 01 03 c3 89 0d ?? ?? ?? ?? a3 ?? ?? ?? ?? 89 8c 16 5f de ff ff a1 ?? ?? ?? ?? 8b 2d ?? ?? ?? ?? bb 53 00 00 00 2b d8 8b cd 2b cb 83 c1 1d 89 1d ?? ?? ?? ?? 3b c8 75 } 		$a_01_1 = {43 72 65 61 74 65 53 65 6d 61 70 68 6f 72 65 41 } 		$a_01_2 = {52 65 67 69 73 74 65 72 48 6f 74 4b 65 79 } 		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}