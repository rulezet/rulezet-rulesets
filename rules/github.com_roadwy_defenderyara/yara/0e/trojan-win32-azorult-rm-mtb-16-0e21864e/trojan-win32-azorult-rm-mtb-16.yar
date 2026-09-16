rule Trojan_Win32_Azorult_RM_MTB_16{
	meta:
		description = "Trojan:Win32/Azorult.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 45 e0 89 45 ?? c7 ?? ?? ?? ?? ?? 84 cd 10 fe 8b ?? ?? 33 ?? ?? 89 ?? ?? 8b ?? ?? 33 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}