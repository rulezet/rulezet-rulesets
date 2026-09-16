rule Trojan_Win32_Gozi_GC_MTB_3{
	meta:
		description = "Trojan:Win32/Gozi.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 c4 08 8b 55 ?? 8b 45 ?? 8d 8c 10 ?? ?? ?? ?? 89 4d ?? 8b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 8b 45 [0-30] 8b 4d } 		$a_02_1 = {8b ff c7 05 ec [0-30] 01 05 [0-30] 8b ff a1 [0-30] 8b 0d [0-25] 89 08 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}