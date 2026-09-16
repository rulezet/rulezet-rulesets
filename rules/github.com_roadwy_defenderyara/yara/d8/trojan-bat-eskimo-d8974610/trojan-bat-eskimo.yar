rule Trojan_BAT_Eskimo{
	meta:
		description = "Trojan:BAT/Eskimo,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 74 65 61 6d 53 74 65 61 6c 65 72 2e } 		$a_01_1 = {73 65 74 5f 55 73 65 72 41 67 65 6e 74 } 		$a_01_2 = {67 65 74 5f 4b 65 79 73 } 		$a_01_3 = {67 65 74 5f 49 74 65 6d } 	condition:
		((#a_00_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}