rule Trojan_Win32_Azorult_RTH_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 ee 05 03 [0-05] 83 [0-05] 1b 8d [0-03] 89 [0-05] c7 05 [0-05] fc 03 cf ff } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}