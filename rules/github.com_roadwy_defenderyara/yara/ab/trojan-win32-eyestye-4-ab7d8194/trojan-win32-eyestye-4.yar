rule Trojan_Win32_EyeStye_4{
	meta:
		description = "Trojan:Win32/EyeStye,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 46 20 3b 20 25 73 20 3b 20 25 73 20 3b 20 25 73 } 		$a_01_1 = {73 70 79 45 59 45 } 		$a_01_2 = {5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 70 72 6f 66 69 6c 65 73 2e 69 6e 69 } 		$a_01_3 = {54 61 6b 65 42 6f 74 47 75 69 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}