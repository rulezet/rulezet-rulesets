rule Trojan_Win32_Startpage_KR_2{
	meta:
		description = "Trojan:Win32/Startpage.KR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 52 74 6b 53 59 55 64 70 2e 65 78 65 20 66 69 6c 6c 64 65 6c 65 74 65 20 20 } 		$a_01_1 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 00 00 5c 5c 2e 5c 53 4d 41 52 54 56 53 44 00 } 		$a_01_2 = {53 74 61 72 74 20 50 61 67 65 22 3d 22 68 74 74 70 3a 2f 2f 77 77 77 2e 68 61 65 31 32 33 2e 63 6f 6d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}