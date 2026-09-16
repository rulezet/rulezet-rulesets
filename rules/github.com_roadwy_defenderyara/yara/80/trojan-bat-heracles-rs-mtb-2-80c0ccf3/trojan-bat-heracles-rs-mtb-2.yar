rule Trojan_BAT_Heracles_RS_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.RS!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 28 02 00 00 06 0c 28 27 00 00 0a 06 6f 28 00 00 0a 0d 73 29 00 00 0a 13 04 16 13 05 2b 1d } 		$a_01_1 = {11 04 11 05 09 11 05 09 8e 69 5d 91 08 11 05 91 61 d2 6f 2a 00 00 0a 11 05 17 58 13 05 11 05 08 8e 69 32 dc } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}