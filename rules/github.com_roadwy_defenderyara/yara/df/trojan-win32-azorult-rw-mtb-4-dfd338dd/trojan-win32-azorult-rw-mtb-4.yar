rule Trojan_Win32_Azorult_RW_MTB_4{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 eb c7 05 ?? ?? ?? ?? ee 3d ea f4 03 9d ?? ?? ?? ?? 33 da 81 3d ?? ?? ?? ?? b7 01 00 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}