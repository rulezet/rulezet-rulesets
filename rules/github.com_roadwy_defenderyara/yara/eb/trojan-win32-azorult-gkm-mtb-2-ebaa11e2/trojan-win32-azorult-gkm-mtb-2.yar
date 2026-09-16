rule Trojan_Win32_Azorult_GKM_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {05 c3 9e 26 00 a3 ?? ?? ?? ?? 0f b7 1d ?? ?? ?? ?? 81 e3 ff 7f 00 00 81 3d ?? ?? ?? ?? e7 08 00 00 75 [0-20] 30 1c ?? 83 ff 19 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}