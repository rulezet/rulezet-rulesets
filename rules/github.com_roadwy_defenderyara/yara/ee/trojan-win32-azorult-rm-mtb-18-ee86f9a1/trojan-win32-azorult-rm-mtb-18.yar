rule Trojan_Win32_Azorult_RM_MTB_18{
	meta:
		description = "Trojan:Win32/Azorult.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2e ce 50 91 e8 ?? ?? ?? ?? 8b [0-05] 8b ?? 8b ?? d3 ?? 03 [0-04] 33 ?? 83 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}