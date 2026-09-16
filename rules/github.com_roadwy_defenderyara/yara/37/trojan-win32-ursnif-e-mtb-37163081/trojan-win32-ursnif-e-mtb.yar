rule Trojan_Win32_Ursnif_E_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b ff c7 05 [0-30] 01 05 [0-30] 8b ff a1 [0-20] 8b 0d [0-20] 89 08 } 		$a_02_1 = {8b 45 fc 89 45 ?? 8b 0d [0-20] 03 4d ?? 89 0d [0-20] 8b 55 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}