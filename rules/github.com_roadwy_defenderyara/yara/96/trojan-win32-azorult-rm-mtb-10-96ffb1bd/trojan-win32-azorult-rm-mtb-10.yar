rule Trojan_Win32_Azorult_RM_MTB_10{
	meta:
		description = "Trojan:Win32/Azorult.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 2e eb ed 8b ?? ?? 8b fb d3 ef c7 ?? ?? ?? ?? ?? 2e ce 50 91 03 ?? ?? 3d eb 03 00 00 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}