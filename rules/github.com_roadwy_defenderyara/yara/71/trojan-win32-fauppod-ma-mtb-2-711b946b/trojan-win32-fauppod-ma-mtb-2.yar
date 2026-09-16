rule Trojan_Win32_Fauppod_MA_MTB_2{
	meta:
		description = "Trojan:Win32/Fauppod.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {e8 de ff ff ff 40 90 0a 2a 00 e8 ?? ?? ff ff 8d 05 ?? ?? ?? ?? 89 18 89 f0 01 05 ?? ?? ?? ?? 89 ea 01 15 } 		$a_01_1 = {89 45 00 55 89 e5 83 e4 f8 83 ec 70 31 c0 89 44 24 60 8b 44 24 60 } 		$a_01_2 = {8b 45 e8 8b 4d f0 8a 14 01 8b 75 ec 88 14 06 05 01 00 00 00 8b 7d f4 39 f8 89 45 e8 75 e2 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}