rule Trojan_Win32_Alureon_gen_C{
	meta:
		description = "Trojan:Win32/Alureon.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a d1 80 c2 ?? 30 14 ?? 83 c1 01 3b ?? 72 f1 c3 } 		$a_00_1 = {5b 72 75 6e 73 5f 63 6f 75 6e 74 5f } 		$a_00_2 = {5b 75 72 6c 73 5f 74 6f 5f 73 65 72 66 5f } 		$a_00_3 = {5b 72 65 66 73 5f 74 6f 5f 63 68 61 6e 67 65 5f } 	condition:
		((#a_03_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=11
 
}