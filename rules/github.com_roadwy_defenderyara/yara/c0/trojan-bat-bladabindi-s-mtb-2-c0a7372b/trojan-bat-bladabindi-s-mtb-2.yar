rule Trojan_BAT_Bladabindi_S_MTB_2{
	meta:
		description = "Trojan:BAT/Bladabindi.S!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 34 00 00 0a 72 47 01 00 70 28 35 00 00 0a 17 8d 28 00 00 01 25 16 1f 3a 9d 6f 36 00 00 0a 0a 06 8e 69 17 da 0c 16 0b 2b 14 06 16 9a 80 0e 00 00 04 06 17 9a 80 18 00 00 04 07 17 d6 0b 07 08 31 e8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}