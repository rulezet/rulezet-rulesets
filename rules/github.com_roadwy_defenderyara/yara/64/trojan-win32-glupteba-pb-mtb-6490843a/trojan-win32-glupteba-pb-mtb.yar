rule Trojan_Win32_Glupteba_PB_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 ff 15 [0-04] 8b [0-03] 8b [0-03] 33 ?? 33 ?? 8d [0-06] 89 [0-03] e8 [0-04] 8b [0-06] 29 [0-03] 83 [0-07] 0f 85 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}