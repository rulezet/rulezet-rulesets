rule Trojan_Win32_Farfli_DA_MTB{
	meta:
		description = "Trojan:Win32/Farfli.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 74 8a 14 08 80 f2 62 88 14 08 40 3b c5 72 } 		$a_01_1 = {33 36 30 5c 33 36 30 53 61 66 65 5c 53 42 33 36 30 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}