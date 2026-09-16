rule Trojan_Win64_SLoader_A{
	meta:
		description = "Trojan:Win64/SLoader.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_80_0 = {73 73 73 74 20 69 6b 20 76 65 72 73 74 6f 70 20 6d 65 20 69 6e 20 6e 6f 74 65 70 61 64 2b 2b } 		$a_80_1 = {2f 64 32 2e 62 69 6e } 		$a_80_2 = {6e 69 65 74 6d 61 6c 69 63 69 6f 75 73 2e 6e 6c } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=2
 
}