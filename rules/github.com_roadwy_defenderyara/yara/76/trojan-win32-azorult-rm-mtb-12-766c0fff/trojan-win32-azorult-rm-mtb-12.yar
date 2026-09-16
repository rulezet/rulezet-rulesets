rule Trojan_Win32_Azorult_RM_MTB_12{
	meta:
		description = "Trojan:Win32/Azorult.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 89 45 ?? 8b ?? ?? 01 ?? ?? c7 ?? ?? ?? ?? ?? 84 cd 10 fe 8b ?? ?? 51 8d 55 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}