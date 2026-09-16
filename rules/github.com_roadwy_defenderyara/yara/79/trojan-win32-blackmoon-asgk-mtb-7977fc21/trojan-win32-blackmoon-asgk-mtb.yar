rule Trojan_Win32_BlackMoon_ASGK_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.ASGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {83 c4 04 b8 32 63 47 00 89 45 f4 8d 45 f4 50 6a 01 b8 3c 63 47 00 89 45 f0 8d 45 f0 50 8d 45 fc 50 8b 04 24 8b 00 8b 00 ff 90 e0 00 00 00 8b 5d f0 85 db } 		$a_01_1 = {83 c4 04 6a 00 6a 00 6a 00 68 31 00 01 00 6a 00 ff 75 d0 68 02 00 00 00 bb 90 09 00 00 e8 } 		$a_03_2 = {68 25 00 00 00 68 15 4d 05 04 68 06 00 00 00 e8 ?? ?? 04 00 83 c4 0c e9 } 		$a_01_3 = {42 6c 61 63 6b 4d 6f 6f 6e 20 52 75 6e 54 69 6d 65 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1) >=10
 
}