rule Trojan_BAT_RedLine_MI_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {09 03 16 03 8e 69 28 9b 01 00 06 2a 0a 38 65 ff ff ff 0b 38 6d ff ff ff 0c 2b 92 } 		$a_01_1 = {57 dd a2 2b 09 0f 00 00 00 d8 00 23 00 06 00 00 01 00 00 00 84 00 00 00 92 00 00 00 72 01 00 00 c6 } 		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } 		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}