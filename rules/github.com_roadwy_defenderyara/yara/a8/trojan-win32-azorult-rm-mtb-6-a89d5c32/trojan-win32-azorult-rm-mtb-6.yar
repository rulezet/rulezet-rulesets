rule Trojan_Win32_Azorult_RM_MTB_6{
	meta:
		description = "Trojan:Win32/Azorult.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e2 04 03 [0-05] 3d a9 0f 00 00 75 [0-05] c7 [0-05] 40 2e eb ed 3d } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}