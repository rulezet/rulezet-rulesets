rule Trojan_Win32_Azorult_RM_MTB_3{
	meta:
		description = "Trojan:Win32/Azorult.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e0 01 ?? ?? c7 ?? ?? ?? ?? ?? 84 cd 10 fe 8b ?? ?? 33 ?? ?? 89 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}