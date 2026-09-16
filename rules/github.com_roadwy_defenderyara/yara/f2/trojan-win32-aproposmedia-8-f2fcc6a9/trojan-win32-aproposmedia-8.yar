rule Trojan_Win32_AproposMedia_8{
	meta:
		description = "Trojan:Win32/AproposMedia,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 47 65 6e 65 72 69 63 73 2e 64 6c 6c 00 } 		$a_01_1 = {4c 6f 67 67 69 6e 67 40 57 69 6e 47 65 6e 65 72 69 63 73 } 		$a_01_2 = {57 69 6e 64 6f 77 73 48 6f 6f 6b 73 53 74 6f 72 61 67 65 3a } 		$a_01_3 = {49 6e 74 65 72 6e 65 74 43 72 61 63 6b 55 72 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}