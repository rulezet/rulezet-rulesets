rule Trojan_Win32_Azorult_RM_MTB_4{
	meta:
		description = "Trojan:Win32/Azorult.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 fb 61 36 13 01 0f [0-05] eb [0-05] a1 [0-04] a3 [0-04] 33 ff 81 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}