rule Trojan_Win32_Azorult_RM_MTB_13{
	meta:
		description = "Trojan:Win32/Azorult.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 45 ?? 33 c2 89 45 ?? 81 fb a3 01 00 00 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}