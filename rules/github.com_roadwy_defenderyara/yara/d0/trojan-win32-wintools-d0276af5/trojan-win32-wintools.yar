rule Trojan_Win32_WinTools{
	meta:
		description = "Trojan:Win32/WinTools,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 53 4b 5f 45 4e 41 42 4c 45 5f 48 4f 4d 45 50 41 47 45 } 		$a_01_1 = {41 64 53 57 6e 64 50 72 6f 63 } 		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 57 69 6e 54 6f 6f 6c 73 } 		$a_01_3 = {57 54 6f 6f 6c 73 42 2e 64 6c 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}