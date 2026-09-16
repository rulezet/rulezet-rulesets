rule Trojan_Win32_GhostRAT_MA_MTB{
	meta:
		description = "Trojan:Win32/GhostRAT.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 ec 0c 0f b6 45 10 99 b9 ?? ?? ?? ?? 53 f7 f9 56 57 89 65 f0 80 c2 17 83 65 ec 00 88 55 13 8b 45 ec 3b 45 0c 73 } 		$a_03_1 = {8b 45 08 8a 08 32 4d 13 02 4d 13 88 08 40 89 45 08 b8 ?? ?? ?? ?? c3 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}