rule Trojan_Win32_Azorult_RM_MTB_5{
	meta:
		description = "Trojan:Win32/Azorult.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 ec 15 00 00 e8 ?? ?? ?? ?? 53 55 56 33 f6 81 3d ?? ?? ?? ?? 77 01 00 00 57 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}