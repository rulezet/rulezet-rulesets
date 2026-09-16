rule Trojan_Win32_Ursnif_GC_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 02 8b 4d ?? 8d 54 01 ?? 8b 45 ?? 89 10 8b 4d ?? 8b 11 83 ea ?? 8b 45 ?? 89 10 8b e5 } 		$a_02_1 = {8b ff c7 05 [0-30] 01 05 [0-20] 8b ff 8b 0d [0-20] 8b 15 [0-20] 89 11 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}