rule Trojan_Win32_Zenpak_G_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpak.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 1c 02 2b 4d ?? 8b 75 ?? 88 1c 06 01 c8 8b 4d ?? 39 c8 89 45 ?? 74 ?? 90 13 8b 45 ?? b9 ?? ?? ?? ?? 8b 55 } 		$a_02_1 = {88 1c 06 83 c0 ?? c6 45 f1 ?? 8b 7d ?? 39 f8 89 45 [0-10] 90 13 8b 45 [0-10] 8b 55 ?? 8a 1c 02 [0-10] 8b 75 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}