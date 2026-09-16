rule Trojan_Win64_ShellcodeRunner_GM_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 78 6f 72 44 65 63 72 79 70 74 } 		$a_01_1 = {6d 61 69 6e 2e 78 6f 72 45 6e 63 72 79 70 74 } 		$a_01_2 = {6d 61 69 6e 2e 67 65 6e 65 72 61 74 65 4b 65 79 } 		$a_01_3 = {6d 61 69 6e 2e 62 61 73 65 36 34 44 65 63 6f 64 65 } 		$a_01_4 = {6d 61 69 6e 2e 64 65 63 72 79 70 74 41 45 53 } 		$a_01_5 = {6d 61 69 6e 2e 64 6f 77 6e 6c 6f 61 64 44 61 74 61 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2) >=9
 
}