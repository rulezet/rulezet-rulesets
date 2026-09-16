rule Trojan_Win32_Azorult_RT_MTB_17{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e1 04 89 [0-05] 8b [0-05] 01 [0-05] 8b [0-05] 03 [0-05] 89 [0-05] 81 [0-05] be 01 00 00 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}