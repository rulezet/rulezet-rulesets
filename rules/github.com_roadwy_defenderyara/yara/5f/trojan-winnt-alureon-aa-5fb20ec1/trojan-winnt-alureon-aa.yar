rule Trojan_WinNT_Alureon_AA{
	meta:
		description = "Trojan:WinNT/Alureon.AA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {bb 42 4b 46 53 53 c1 e0 09 50 6a 00 ff 15 } 		$a_01_1 = {89 48 08 89 48 58 89 48 34 e8 } 		$a_01_2 = {5b 69 6e 6a 65 63 74 73 5f 65 6e 64 5d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}