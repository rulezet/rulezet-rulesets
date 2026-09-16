rule Trojan_Win32_Azorult_RM_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ee 3d ea f4 03 [0-05] 33 [0-05] 89 [0-05] a3 01 00 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}