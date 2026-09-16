rule Trojan_Win32_Azorult_RM_MTB_25{
	meta:
		description = "Trojan:Win32/Azorult.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea c7 05 ?? ?? ?? ?? 2e ce 50 91 89 55 ?? 8b 85 ?? ?? ?? ?? 01 45 ?? 8b 4d ?? 33 cb 33 4d ?? 8d 85 ?? ?? ?? ?? 89 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}