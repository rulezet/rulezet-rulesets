rule Trojan_BAT_RedLine_MC_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {13 04 12 03 12 00 28 02 00 00 06 74 01 00 00 1b 13 05 11 05 28 04 00 00 0a 13 06 11 04 13 07 28 01 00 00 0a 1f 33 8d 02 00 00 01 25 d0 05 00 00 04 } 		$a_01_1 = {43 6f 6e 66 69 67 75 72 61 74 69 6f 6e 46 69 6c 65 53 6f 75 72 63 65 57 61 74 63 68 65 72 } 		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}