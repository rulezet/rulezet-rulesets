rule Trojan_Win32_Dridex_NC_MTB{
	meta:
		description = "Trojan:Win32/Dridex.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 11 8b e5 5d c3 90 09 30 00 ff [0-05] 8f [0-05] 33 [0-05] c7 05 [0-08] 8b [0-03] 01 15 [0-04] 8b 0d [0-04] 8b 15 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}