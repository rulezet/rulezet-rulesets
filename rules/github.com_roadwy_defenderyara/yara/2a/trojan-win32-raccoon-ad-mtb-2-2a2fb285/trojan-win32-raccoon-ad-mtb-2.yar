rule Trojan_Win32_Raccoon_AD_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 0c 33 44 24 1c c7 05 ?? ?? ?? ?? 00 00 00 00 31 44 24 10 89 44 24 0c 8b 44 24 10 01 05 ?? ?? ?? ?? 8b 44 24 10 29 44 24 14 8b 54 24 14 c1 e2 04 89 54 24 0c 8b 44 24 ?? 01 44 24 0c 8b 44 24 14 03 44 24 20 } 		$a_03_1 = {8b 54 24 1c 31 54 24 0c c1 e9 05 03 [0-03] c7 05 ?? ?? ?? ?? b4 02 d7 cb c7 05 ?? ?? ?? ?? ff ff ff ff 89 4c 24 10 8b 44 24 10 31 44 24 0c 8b 44 24 0c 29 44 24 18 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}