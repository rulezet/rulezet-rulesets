rule Trojan_Win32_RedLine_BQ_MTB{
	meta:
		description = "Trojan:Win32/RedLine.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 75 dc 8b 5d d4 8b 7d d0 83 e7 03 8a 87 [0-04] 30 04 33 46 eb } 		$a_01_1 = {6c 6f 67 67 69 6e 67 2e 62 69 6e } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}