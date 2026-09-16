rule Trojan_Win32_CryptInject_BE_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {41 50 50 44 41 54 41 [0-20] 25 73 5c 62 6f 78 } 		$a_02_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 64 6f 77 73 [0-50] 41 70 70 49 6e 69 74 5f 44 4c 4c 73 [0-20] 25 73 5c 62 6f 78 2e 6c 6e 6b } 		$a_02_2 = {6c 61 75 6e 63 68 [0-20] 50 72 6f 67 72 61 6d 46 69 6c 65 73 [0-20] 64 72 6f 70 [0-20] 44 4c 4c } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}