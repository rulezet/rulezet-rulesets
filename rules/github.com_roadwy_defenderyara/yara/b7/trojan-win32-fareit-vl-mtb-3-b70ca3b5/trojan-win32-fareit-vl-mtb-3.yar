rule Trojan_Win32_Fareit_VL_MTB_3{
	meta:
		description = "Trojan:Win32/Fareit.VL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 04 0f 53 5b e8 ?? ?? ?? ?? 80 fd ?? 89 04 0f 66 3d ?? ?? 66 83 e9 ?? 66 3d ?? ?? 81 f9 ?? ?? ?? ?? 75 90 09 03 00 80 fc } 		$a_02_1 = {31 f0 66 3d ?? ?? c3 90 09 04 00 66 3d } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}