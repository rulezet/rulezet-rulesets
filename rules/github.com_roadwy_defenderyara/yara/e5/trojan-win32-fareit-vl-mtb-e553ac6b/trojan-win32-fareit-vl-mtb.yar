rule Trojan_Win32_Fareit_VL_MTB{
	meta:
		description = "Trojan:Win32/Fareit.VL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {51 59 8b 04 0f 66 3d ?? ?? e8 ?? ?? ?? ?? 52 5a 89 04 0f 66 81 f9 ?? ?? 66 83 e9 ?? 66 3d ?? ?? 81 f9 ?? ?? ?? ?? 75 } 		$a_02_1 = {31 f0 66 81 fa ?? ?? c3 90 09 04 00 66 3d } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}