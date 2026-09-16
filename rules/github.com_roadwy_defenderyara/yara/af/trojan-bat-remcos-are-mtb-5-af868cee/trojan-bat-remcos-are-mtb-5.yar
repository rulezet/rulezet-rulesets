rule Trojan_BAT_Remcos_ARE_MTB_5{
	meta:
		description = "Trojan:BAT/Remcos.ARE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 26 7e 03 00 00 04 18 6f 42 00 00 0a 00 02 02 02 03 03 03 04 03 04 0e 04 28 08 00 00 06 0a 2b 00 } 		$a_01_1 = {7e 04 00 00 04 28 3e 00 00 0a 02 6f 3f 00 00 0a 6f 40 00 00 0a 0a 7e 03 00 00 04 06 25 0b 6f 41 00 00 0a 00 07 0c 2b 00 08 2a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}