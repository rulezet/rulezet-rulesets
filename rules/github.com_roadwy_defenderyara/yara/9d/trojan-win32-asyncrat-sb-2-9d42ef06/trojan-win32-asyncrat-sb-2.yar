rule Trojan_Win32_AsyncRAT_SB_2{
	meta:
		description = "Trojan:Win32/AsyncRAT.SB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {41 73 79 6e 63 43 6c 69 65 6e 74 } 		$a_80_1 = {6d 61 73 74 65 72 4b 65 79 20 63 61 6e 20 6e 6f 74 20 62 65 20 6e 75 6c 6c 20 6f 72 20 65 6d 70 74 79 } 		$a_80_2 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 66 20 2f 73 63 20 6f 6e 6c 6f 67 6f 6e 20 2f 72 6c 20 68 69 67 68 65 73 74 } 		$a_01_3 = {bf eb 1e 56 fb cd 97 3b b2 19 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}