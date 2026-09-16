rule Trojan_Win32_Farfli_MC_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_01_0 = {a9 94 39 11 ed f5 57 42 ed f5 57 42 ed f5 57 42 82 ea 5c 42 e4 f5 57 42 82 ea 5d 42 eb f5 57 42 6e e9 59 42 c1 f5 57 42 96 e9 5b 42 e8 f5 57 42 } 		$a_01_1 = {43 6f 6f 6b 69 65 3a 20 25 73 } 		$a_01_2 = {61 6e 6f 6e 79 6d 6f 75 73 40 31 32 33 2e 63 6f 6d } 		$a_01_3 = {5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } 		$a_01_4 = {47 65 74 53 63 72 6f 6c 6c 50 6f 73 } 		$a_01_5 = {49 73 57 6f 77 36 34 50 72 6f 63 65 73 73 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=13
 
}