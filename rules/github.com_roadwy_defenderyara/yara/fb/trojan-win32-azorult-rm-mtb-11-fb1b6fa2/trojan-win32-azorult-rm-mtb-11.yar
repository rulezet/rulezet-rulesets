rule Trojan_Win32_Azorult_RM_MTB_11{
	meta:
		description = "Trojan:Win32/Azorult.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 e9 12 c9 23 00 89 ?? ?? 8b [0-19] c7 [0-05] fc 03 cf ff 81 [0-05] e3 00 00 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}