rule Trojan_BAT_Discoste_RS_MTB_2{
	meta:
		description = "Trojan:BAT/Discoste.RS!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {02 72 de 00 00 70 28 08 00 00 06 28 0d 00 00 06 2a } 		$a_01_1 = {03 73 23 00 00 0a 28 24 00 00 0a 6f 25 00 00 0a 6f 26 00 00 0a 73 27 00 00 0a 0a 06 6f 28 00 00 0a 0b de 0d 06 2c 06 06 6f 19 00 00 0a dc 26 de ce } 		$a_01_2 = {02 28 07 00 00 06 0a 28 21 00 00 0a 06 6f 22 00 00 0a 2a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}