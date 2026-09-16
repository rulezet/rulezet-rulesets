rule Trojan_Win32_Dridex_NA_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {89 08 5d c3 90 0a 25 00 33 [0-05] c7 05 [0-08] 01 15 [0-04] a1 [0-04] 8b } 		$a_02_1 = {83 c2 01 89 [0-05] eb 90 09 24 00 ff [0-05] 03 [0-05] 8b [0-05] 8b [0-05] 8a [0-03] 88 [0-03] 8b 15 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}