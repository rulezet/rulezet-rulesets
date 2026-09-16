rule Trojan_Win32_Azorult_RM_MTB_27{
	meta:
		description = "Trojan:Win32/Azorult.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {fe 93 8d 6a 8b [0-14] 03 cb 33 c1 31 [0-05] 81 [0-05] a3 01 00 00 } 		$a_03_1 = {c1 ea 05 03 55 ?? 83 [0-05] 1b 8b c2 89 45 ?? c7 [0-05] fc 03 cf ff } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}