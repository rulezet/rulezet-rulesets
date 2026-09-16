rule Trojan_BAT_FileCoder_ARAX_MTB_2{
	meta:
		description = "Trojan:BAT/FileCoder.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 61 6e 73 6f 6d 77 61 72 65 50 4f 43 } 		$a_01_1 = {65 6e 63 72 79 70 74 46 6f 6c 64 65 72 43 6f 6e 74 65 6e 74 73 } 		$a_01_2 = {64 72 6f 70 52 61 6e 73 6f 6d 4c 65 74 74 65 72 } 		$a_01_3 = {74 78 74 42 69 74 63 6f 69 6e 41 64 64 72 65 73 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=6
 
}