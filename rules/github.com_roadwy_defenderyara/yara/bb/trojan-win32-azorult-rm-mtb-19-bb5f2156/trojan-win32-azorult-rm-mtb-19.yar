rule Trojan_Win32_Azorult_RM_MTB_19{
	meta:
		description = "Trojan:Win32/Azorult.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 fe 93 8d 6a 8b 55 ?? 33 d1 33 d3 8d 8d ?? ?? ?? ?? 89 55 ?? e8 ?? ?? ?? ?? 89 ?? ?? 25 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}