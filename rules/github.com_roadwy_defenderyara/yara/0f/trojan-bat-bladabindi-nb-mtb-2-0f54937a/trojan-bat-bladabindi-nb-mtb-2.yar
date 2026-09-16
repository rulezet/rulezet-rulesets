rule Trojan_BAT_Bladabindi_NB_MTB_2{
	meta:
		description = "Trojan:BAT/Bladabindi.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 6f 96 00 00 0a 28 a9 01 00 06 02 7b c3 01 00 04 6f a9 01 00 0a 13 09 11 09 39 dd 00 00 00 07 6f 96 00 00 0a 02 7b c3 01 00 04 28 aa 01 00 06 13 04 02 7b c1 01 00 04 13 06 11 06 14 fe 01 16 fe 01 13 09 11 09 2c 2a } 		$a_01_1 = {8d 05 00 00 01 13 07 11 07 16 16 8c 4e 00 00 01 a2 00 11 07 14 28 1a 01 00 0a 74 18 00 00 1b 6f f4 01 00 06 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}