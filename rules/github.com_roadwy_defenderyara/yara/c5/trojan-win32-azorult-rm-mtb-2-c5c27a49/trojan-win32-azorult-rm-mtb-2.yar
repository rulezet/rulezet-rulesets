rule Trojan_Win32_Azorult_RM_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 fe 93 8d 6a 33 d1 31 ?? ?? 8b ?? ?? 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}