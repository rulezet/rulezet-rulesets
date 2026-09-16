rule Trojan_Win32_WinTools_2{
	meta:
		description = "Trojan:Win32/WinTools,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } 		$a_01_1 = {57 65 62 53 65 61 72 63 68 20 54 6f 6f 6c 62 61 72 5c } 		$a_01_2 = {43 4c 53 49 44 5c 7b 00 ff ff ff ff 01 00 00 00 2d 00 00 00 ff ff ff ff 06 00 00 00 2d 42 32 33 44 2d 00 00 ff ff ff ff 01 00 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}