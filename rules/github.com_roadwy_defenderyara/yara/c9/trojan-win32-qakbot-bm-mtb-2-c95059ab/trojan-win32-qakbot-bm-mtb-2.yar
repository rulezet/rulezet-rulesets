rule Trojan_Win32_QakBot_BM_MTB_2{
	meta:
		description = "Trojan:Win32/QakBot.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 49 6e 73 74 61 6c 6c } 		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 		$a_01_2 = {48 69 65 66 70 6c 6e 42 61 79 64 6f 66 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}