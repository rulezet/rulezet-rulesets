rule Trojan_Win32_Azorult_AA_MTB{
	meta:
		description = "Trojan:Win32/Azorult.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {66 85 c0 46 3d ?? ?? ?? ?? ff 37 3d ?? ?? ?? ?? 59 81 ff ?? ?? ?? ?? e8 ?? ?? 00 00 85 ff 39 c1 75 } 		$a_02_1 = {51 66 81 fa ?? ?? 31 34 24 66 81 fa ?? ?? 59 66 85 db c3 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}