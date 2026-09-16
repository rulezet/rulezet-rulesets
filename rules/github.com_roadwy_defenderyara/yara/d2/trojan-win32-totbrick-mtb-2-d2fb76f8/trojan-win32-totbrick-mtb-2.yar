rule Trojan_Win32_Totbrick_MTB_2{
	meta:
		description = "Trojan:Win32/Totbrick!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {83 ee 08 8b da 8b ce d3 fb 47 85 f6 88 5c 07 ff 75 ?? 8b 4c 24 ?? 83 c5 04 49 89 4c 24 ?? 0f 85 ?? ?? ff ff } 		$a_02_1 = {33 d2 8b c1 bd ?? 00 00 00 f7 f5 8a 04 1a 30 04 31 41 3b cf 75 } 		$a_02_2 = {33 d2 8b c1 bf ?? 00 00 00 f7 f7 8a ?? 31 8a ?? ?? ?? ?? ?? 32 ?? 88 ?? 31 41 81 f9 ?? ?? ?? ?? 75 } 		$a_02_3 = {33 d2 8b c1 f7 f3 0f b6 04 2a 8b 54 8c 10 03 c7 03 c2 8b f8 81 e7 ?? ?? ?? ?? 79 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=2
 
}