rule Trojan_Win32_Urelas_C{
	meta:
		description = "Trojan:Win32/Urelas.C,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {40 3d e0 01 00 00 72 ee 81 7c 24 08 4d 53 4d 50 75 } 		$a_01_1 = {25 00 73 00 5c 00 25 00 73 00 2e 00 65 00 78 00 65 00 00 00 } 		$a_01_2 = {67 00 6f 00 6c 00 66 00 69 00 6e 00 66 00 6f 00 2e 00 69 00 6e 00 69 00 00 00 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}