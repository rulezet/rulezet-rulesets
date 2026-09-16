rule Trojan_Win32_Farfli_ME_MTB{
	meta:
		description = "Trojan:Win32/Farfli.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_03_0 = {c6 45 ed 53 c6 45 ee 48 c6 45 ef 45 c6 45 f0 4c c6 45 f1 4c c6 45 f2 2e c6 45 f3 54 c6 45 f4 58 c6 45 f5 54 c6 45 f6 00 8d 4d dc 51 68 ?? ?? ?? ?? e8 } 		$a_01_1 = {53 00 75 00 70 00 65 00 72 00 4d 00 61 00 72 00 6b 00 65 00 74 00 73 00 2e 00 45 00 58 00 45 00 } 		$a_01_2 = {53 65 74 43 61 70 74 75 72 65 } 		$a_01_3 = {53 63 72 65 65 6e 54 6f 43 6c 69 65 6e 74 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=10
 
}