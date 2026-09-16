rule Trojan_Win32_Linkoptimizer{
	meta:
		description = "Trojan:Win32/Linkoptimizer,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 00 00 31 2e 64 6c 6c 00 00 00 5c 00 00 00 43 3a 5c 00 63 3a 5c 77 69 6e 64 6f 77 73 00 00 77 69 6e 64 69 72 00 00 53 59 53 54 45 4d 52 4f 4f 54 00 00 5c 4c 69 6e 6b 4f 70 74 69 6d 69 7a 65 72 2e 64 6c 6c 00 00 5c 4c 69 6e 6b 4f 70 74 69 6d 69 7a 65 72 00 00 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}