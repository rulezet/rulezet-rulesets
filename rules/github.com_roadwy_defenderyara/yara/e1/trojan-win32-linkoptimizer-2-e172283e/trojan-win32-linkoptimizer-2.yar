rule Trojan_Win32_Linkoptimizer_2{
	meta:
		description = "Trojan:Win32/Linkoptimizer,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 00 00 5c 4c 69 6e 6b 4f 70 74 69 6d 69 7a 65 72 2e 64 6c 6c 00 00 5c 4c 69 6e 6b 4f 70 74 69 6d 69 7a 65 72 00 00 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 00 00 00 00 50 72 6f 67 72 61 6d 46 69 6c 65 73 00 } 		$a_01_1 = {6e 75 6c 00 00 4f 70 65 6e 00 00 00 00 2f 63 20 64 65 6c 20 00 43 4f 4d 53 50 45 43 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}