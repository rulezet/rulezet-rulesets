rule Trojan_Win32_Raccrypt_GI_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {8a 94 31 36 23 01 00 88 14 30 81 c4 ?? ?? ?? ?? c3 } 		$a_00_1 = {51 c7 04 24 02 00 00 00 8b 44 24 08 01 04 24 83 2c 24 02 8b 04 24 31 01 59 c2 } 		$a_02_2 = {b4 02 d7 cb c7 05 ?? ?? ?? ?? ff ff ff ff 90 0a 10 00 c7 05 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}