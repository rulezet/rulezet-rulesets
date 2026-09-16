rule Trojan_Win32_Gozi_GD_MTB_3{
	meta:
		description = "Trojan:Win32/Gozi.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b ff c7 05 [0-30] 01 1d [0-20] 8b ff a1 [0-10] 8b 0d [0-20] 89 08 5f } 		$a_02_1 = {8b 4d fc 89 4d f4 8b 15 [0-20] 03 55 ?? 89 15 [0-20] 8b 45 ?? 89 45 ?? 8b 4d } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}