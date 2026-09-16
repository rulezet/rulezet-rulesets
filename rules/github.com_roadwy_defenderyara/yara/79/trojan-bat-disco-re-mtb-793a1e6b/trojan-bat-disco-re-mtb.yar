rule Trojan_BAT_Disco_RE_MTB{
	meta:
		description = "Trojan:BAT/Disco.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {0a 2b 14 00 11 04 17 58 13 04 11 04 09 8e 69 fe 04 13 05 11 05 2d 97 06 0c 2b 00 08 2a } 		$a_01_1 = {73 00 75 00 70 00 65 00 72 00 73 00 65 00 78 00 2e 00 65 00 78 00 65 00 } 		$a_01_2 = {53 65 6e 64 4d 65 73 73 61 67 65 54 6f 44 69 73 63 6f 72 64 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}