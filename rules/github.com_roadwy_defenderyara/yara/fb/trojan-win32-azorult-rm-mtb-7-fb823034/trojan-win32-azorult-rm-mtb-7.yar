rule Trojan_Win32_Azorult_RM_MTB_7{
	meta:
		description = "Trojan:Win32/Azorult.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 89 55 ?? 8b ?? ?? 03 ?? ?? 89 ?? ?? c7 ?? ?? ?? ?? ?? fc 03 cf ff } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}