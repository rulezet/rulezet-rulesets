rule Trojan_Win32_Azorult_RM_MTB_15{
	meta:
		description = "Trojan:Win32/Azorult.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 8b 4d ?? 03 cb c7 05 ?? ?? ?? ?? 2e ce 50 91 03 45 ?? 33 c1 33 c7 83 ?? ?? ?? ?? ?? 27 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}