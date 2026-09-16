rule Trojan_Win32_StopCrypt_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/StopCrypt.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 0c 8b 44 24 24 03 44 24 10 c7 05 ?? ?? ?? ?? 00 00 00 00 33 c6 33 c1 2b f8 89 44 24 10 8b c7 c1 e0 04 } 		$a_01_1 = {8b 44 24 28 01 44 24 0c 8b c7 c1 e8 05 8d 34 3b } 		$a_01_2 = {31 74 24 0c 8b 44 24 10 31 44 24 0c 8b 44 24 0c 29 44 24 14 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}