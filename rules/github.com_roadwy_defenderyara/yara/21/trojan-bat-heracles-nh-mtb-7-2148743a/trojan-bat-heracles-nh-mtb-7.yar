rule Trojan_BAT_Heracles_NH_MTB_7{
	meta:
		description = "Trojan:BAT/Heracles.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 14 00 00 0a 13 09 11 09 6f 0b 00 00 0a 25 2d 0c 26 72 01 00 00 70 73 15 00 00 0a 7a 13 0a 11 0a 6f 16 00 00 0a 8e 69 8d 01 00 00 01 13 0b 11 0b 8e 16 fe 03 13 11 11 11 2c 05 11 0b 16 02 a2 11 0a 14 11 0b 6f 17 00 00 0a } 		$a_01_1 = {45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00 20 00 6e 00 6f 00 74 00 20 00 66 00 6f 00 75 00 6e 00 64 00 21 00 21 00 21 00 21 00 21 00 21 00 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}