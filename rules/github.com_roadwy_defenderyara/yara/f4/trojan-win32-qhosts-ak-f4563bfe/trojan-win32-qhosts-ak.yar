rule Trojan_Win32_QHosts_AK{
	meta:
		description = "Trojan:Win32/QHosts.AK,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 65 23 74 23 63 5c 68 23 6f 23 73 23 74 73 } 		$a_01_1 = {22 44 69 23 73 23 61 62 23 6c 65 23 } 		$a_01_2 = {5c 68 73 74 2e 70 6e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}