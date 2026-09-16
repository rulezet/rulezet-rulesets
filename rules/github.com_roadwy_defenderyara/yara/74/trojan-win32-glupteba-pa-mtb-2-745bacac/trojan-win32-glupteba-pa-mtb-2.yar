rule Trojan_Win32_Glupteba_PA_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {75 31 33 c0 8d [0-03] 51 8d [0-03] 52 50 89 [0-03] 89 [0-03] 89 [0-03] 89 [0-03] 89 [0-03] ff d3 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff d5 57 e8 [0-04] 81 3d [0-08] 75 0e 6a 00 ff 15 [0-04] ff 15 [0-04] 83 c7 08 83 ee 01 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}